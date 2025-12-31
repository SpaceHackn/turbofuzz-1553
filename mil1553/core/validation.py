"""
Protocol Validation

This module provides protocol compliance validation for MIL-STD-1553B messages and words.
It checks for violations of protocol rules and returns detailed validation results.
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from mil1553.core.constants import (
    Severity, ErrorType, TimingConstants,
    MAX_RT_ADDRESS, MAX_SUBADDRESS, BROADCAST_ADDRESS,
    is_valid_rt_address, is_mode_command_subaddress
)
from mil1553.core.word import Word, CommandWord, StatusWord, DataWord
from mil1553.core.message import Message
from mil1553.core.exceptions import ValidationException


@dataclass
class Violation:
    """
    Represents a protocol violation.

    Attributes:
        error_type: Type of error
        severity: Severity level
        description: Human-readable description
        location: Optional location information (e.g., "word 3", "command word")
        details: Additional details dictionary
    """
    error_type: ErrorType
    severity: Severity
    description: str
    location: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        loc = f" at {self.location}" if self.location else ""
        return f"[{self.severity.value.upper()}] {self.error_type.value}{loc}: {self.description}"


@dataclass
class Warning:
    """
    Represents a protocol warning (non-critical issue).

    Attributes:
        message: Warning message
        location: Optional location information
        details: Additional details
    """
    message: str
    location: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        loc = f" at {self.location}" if self.location else ""
        return f"[WARNING]{loc}: {self.message}"


@dataclass
class ValidationResult:
    """
    Result of a validation operation.

    Attributes:
        is_valid: Whether validation passed
        violations: List of violations found
        warnings: List of warnings
        severity: Highest severity level found
        details: Additional validation details
    """
    is_valid: bool
    violations: List[Violation] = field(default_factory=list)
    warnings: List[Warning] = field(default_factory=list)
    severity: Severity = Severity.INFO
    details: Dict[str, Any] = field(default_factory=dict)

    def add_violation(
        self,
        error_type: ErrorType,
        severity: Severity,
        description: str,
        location: Optional[str] = None,
        **details
    ):
        """Add a violation to the result."""
        violation = Violation(
            error_type=error_type,
            severity=severity,
            description=description,
            location=location,
            details=details
        )
        self.violations.append(violation)
        self.is_valid = False

        # Update severity to highest found
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        if severity_order[severity] > severity_order[self.severity]:
            self.severity = severity

    def add_warning(self, message: str, location: Optional[str] = None, **details):
        """Add a warning to the result."""
        warning = Warning(message=message, location=location, details=details)
        self.warnings.append(warning)

    def __str__(self) -> str:
        lines = []
        lines.append(f"Validation Result: {'PASS' if self.is_valid else 'FAIL'}")
        lines.append(f"Severity: {self.severity.value}")

        if self.violations:
            lines.append(f"\nViolations ({len(self.violations)}):")
            for v in self.violations:
                lines.append(f"  {v}")

        if self.warnings:
            lines.append(f"\nWarnings ({len(self.warnings)}):")
            for w in self.warnings:
                lines.append(f"  {w}")

        return "\n".join(lines)


class ProtocolValidator:
    """
    Validates MIL-STD-1553B protocol compliance.

    Performs comprehensive validation of words and messages against
    protocol specifications.
    """

    def __init__(self, strict: bool = True):
        """
        Initialize validator.

        Args:
            strict: If True, applies strict validation rules.
                   If False, allows some protocol deviations.
        """
        self.strict = strict

    def validate_word(self, word: Word, location: Optional[str] = None) -> ValidationResult:
        """
        Validate a single word.

        Args:
            word: Word to validate
            location: Optional location information

        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)

        # Check parity
        if not word.is_valid_parity():
            result.add_violation(
                error_type=ErrorType.PARITY_ERROR,
                severity=Severity.HIGH,
                description=f"Invalid parity: expected {word.calculate_parity()}, got {word.parity}",
                location=location,
                expected=word.calculate_parity(),
                actual=word.parity
            )

        # Check sync pattern
        try:
            if not word._is_valid_sync():
                result.add_violation(
                    error_type=ErrorType.INVALID_SYNC,
                    severity=Severity.HIGH,
                    description=f"Invalid sync pattern: {word.sync:#05b}",
                    location=location,
                    sync=word.sync
                )
        except:
            pass  # Might not have _is_valid_sync implemented

        # Type-specific validation
        if isinstance(word, CommandWord):
            result = self._validate_command_word(word, result, location)
        elif isinstance(word, StatusWord):
            result = self._validate_status_word(word, result, location)
        elif isinstance(word, DataWord):
            result = self._validate_data_word(word, result, location)

        return result

    def _validate_command_word(
        self,
        word: CommandWord,
        result: ValidationResult,
        location: Optional[str]
    ) -> ValidationResult:
        """Validate command word specific fields."""

        # Check RT address
        if not is_valid_rt_address(word.rt_address):
            result.add_violation(
                error_type=ErrorType.INVALID_ADDRESS,
                severity=Severity.CRITICAL,
                description=f"Invalid RT address: {word.rt_address}",
                location=location,
                address=word.rt_address
            )

        # Check subaddress
        if not (0 <= word.subaddress <= MAX_SUBADDRESS):
            result.add_violation(
                error_type=ErrorType.INVALID_SUBADDRESS,
                severity=Severity.HIGH,
                description=f"Invalid subaddress: {word.subaddress}",
                location=location,
                subaddress=word.subaddress
            )

        # Check T/R bit
        if word.transmit_receive not in (0, 1):
            result.add_violation(
                error_type=ErrorType.PROTOCOL_VIOLATION,
                severity=Severity.HIGH,
                description=f"Invalid T/R bit: {word.transmit_receive}",
                location=location,
                tr_bit=word.transmit_receive
            )

        # Check word count
        if not (0 <= word.word_count_mode <= 31):
            result.add_violation(
                error_type=ErrorType.PROTOCOL_VIOLATION,
                severity=Severity.MEDIUM,
                description=f"Invalid word count: {word.word_count_mode}",
                location=location,
                word_count=word.word_count_mode
            )

        # Warnings
        if word.is_broadcast and word.transmit_receive == 1:
            result.add_warning(
                "Broadcast with transmit bit set is unusual",
                location=location
            )

        return result

    def _validate_status_word(
        self,
        word: StatusWord,
        result: ValidationResult,
        location: Optional[str]
    ) -> ValidationResult:
        """Validate status word specific fields."""

        # Check RT address (broadcast not valid for status from RT)
        if word.rt_address == BROADCAST_ADDRESS:
            result.add_violation(
                error_type=ErrorType.INVALID_ADDRESS,
                severity=Severity.HIGH,
                description="Status word cannot have broadcast address (31)",
                location=location,
                address=word.rt_address
            )
        elif not is_valid_rt_address(word.rt_address):
            result.add_violation(
                error_type=ErrorType.INVALID_ADDRESS,
                severity=Severity.CRITICAL,
                description=f"Invalid RT address: {word.rt_address}",
                location=location,
                address=word.rt_address
            )

        # Check reserved bits (should be 0)
        if self.strict and word.reserved != 0:
            result.add_warning(
                f"Reserved bits not zero: {word.reserved:#05b}",
                location=location,
                reserved=word.reserved
            )

        # Flag consistency checks
        if word.message_error:
            result.add_warning(
                "Message error flag is set",
                location=location
            )

        return result

    def _validate_data_word(
        self,
        word: DataWord,
        result: ValidationResult,
        location: Optional[str]
    ) -> ValidationResult:
        """Validate data word specific fields."""

        # Data words have minimal validation beyond parity and sync
        # which are already checked in validate_word()

        return result

    def validate_message(self, message: Message) -> ValidationResult:
        """
        Validate a complete message.

        Args:
            message: Message to validate

        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)

        # Validate structure (already done in Message.__init__, but check again)
        try:
            message._validate_structure()
        except Exception as e:
            result.add_violation(
                error_type=ErrorType.PROTOCOL_VIOLATION,
                severity=Severity.CRITICAL,
                description=f"Message structure invalid: {str(e)}",
                location="message structure"
            )

        # Validate word count consistency
        try:
            message.validate_word_count()
        except Exception as e:
            result.add_violation(
                error_type=ErrorType.WORD_COUNT_MISMATCH,
                severity=Severity.HIGH,
                description=str(e),
                location="word count"
            )

        # Validate all command words
        for i, cmd in enumerate(message.command_words):
            word_result = self.validate_word(cmd, location=f"command word {i}")
            result.violations.extend(word_result.violations)
            result.warnings.extend(word_result.warnings)
            if not word_result.is_valid:
                result.is_valid = False

        # Validate all status words
        for i, status in enumerate(message.status_words):
            word_result = self.validate_word(status, location=f"status word {i}")
            result.violations.extend(word_result.violations)
            result.warnings.extend(word_result.warnings)
            if not word_result.is_valid:
                result.is_valid = False

        # Validate all data words
        for i, data in enumerate(message.data_words):
            word_result = self.validate_word(data, location=f"data word {i}")
            result.violations.extend(word_result.violations)
            result.warnings.extend(word_result.warnings)
            if not word_result.is_valid:
                result.is_valid = False

        # Message-specific validations
        result = self._validate_message_timing(message, result)

        return result

    def _validate_message_timing(
        self,
        message: Message,
        result: ValidationResult
    ) -> ValidationResult:
        """Validate message timing requirements."""

        # Check inter-message gap if specified
        if message.gap_time is not None:
            if message.gap_time < TimingConstants.INTER_MESSAGE_GAP_MIN:
                result.add_violation(
                    error_type=ErrorType.INSUFFICIENT_GAP,
                    severity=Severity.MEDIUM,
                    description=f"Inter-message gap too short: {message.gap_time}μs "
                               f"(min: {TimingConstants.INTER_MESSAGE_GAP_MIN}μs)",
                    location="timing",
                    gap_time=message.gap_time,
                    min_gap=TimingConstants.INTER_MESSAGE_GAP_MIN
                )

        # Check response time for RT messages
        response_time = message.get_response_time()
        if response_time is not None:
            if response_time < TimingConstants.RESPONSE_TIME_MIN:
                result.add_violation(
                    error_type=ErrorType.RESPONSE_TOO_EARLY,
                    severity=Severity.MEDIUM,
                    description=f"Response time too short: {response_time}μs",
                    location="timing"
                )
            elif response_time > TimingConstants.RESPONSE_TIME_MAX:
                result.add_violation(
                    error_type=ErrorType.RESPONSE_TOO_LATE,
                    severity=Severity.MEDIUM,
                    description=f"Response time too long: {response_time}μs",
                    location="timing"
                )

        return result

    def validate_sequence(self, messages: List[Message]) -> ValidationResult:
        """
        Validate a sequence of messages.

        Args:
            messages: List of messages to validate

        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)

        # Validate each message
        for i, msg in enumerate(messages):
            msg_result = self.validate_message(msg)
            result.violations.extend(msg_result.violations)
            result.warnings.extend(msg_result.warnings)
            if not msg_result.is_valid:
                result.is_valid = False

        # Check timing between messages
        for i in range(len(messages) - 1):
            current = messages[i]
            next_msg = messages[i + 1]

            # Check gap time if timestamps available
            if current.timestamp is not None and next_msg.timestamp is not None:
                gap = (next_msg.timestamp - current.timestamp) * 1_000_000  # Convert to μs
                if gap < TimingConstants.INTER_MESSAGE_GAP_MIN:
                    result.add_violation(
                        error_type=ErrorType.INSUFFICIENT_GAP,
                        severity=Severity.MEDIUM,
                        description=f"Gap between messages {i} and {i+1} too short: {gap:.2f}μs",
                        location=f"messages {i}-{i+1}",
                        gap=gap
                    )

        return result


class StrictValidator(ProtocolValidator):
    """Strict protocol validator (no deviations allowed)."""

    def __init__(self):
        super().__init__(strict=True)


class PermissiveValidator(ProtocolValidator):
    """Permissive validator (allows some protocol deviations)."""

    def __init__(self):
        super().__init__(strict=False)
