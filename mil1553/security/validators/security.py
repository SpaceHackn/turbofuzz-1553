"""
Security-Specific Validators for MIL-STD-1553B

This module provides security-focused validation beyond protocol compliance,
including anomaly detection and attack pattern recognition.
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from mil1553.core.message import Message
from mil1553.core.word import Word, CommandWord, StatusWord
from mil1553.core.constants import TimingConstants, BROADCAST_ADDRESS
from mil1553.core.validation import ValidationResult, Violation, Severity
from mil1553.core.exceptions import ValidationException


@dataclass
class Anomaly:
    """
    Represents a security anomaly.

    Attributes:
        anomaly_type: Type of anomaly detected
        severity: Severity level
        description: Human-readable description
        confidence: Confidence score (0.0-1.0)
        indicators: List of indicators that triggered detection
    """
    anomaly_type: str
    severity: Severity
    description: str
    confidence: float
    indicators: List[str]

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.anomaly_type} ({self.confidence:.0%}): {self.description}"


class SecurityValidator:
    """
    Security-focused validator for detecting attacks and anomalies.

    Goes beyond protocol compliance to detect suspicious patterns.
    """

    def __init__(self):
        """Initialize security validator."""
        self.anomalies_detected = []
        self.message_history = []

    def check_anomalies(self, message: Message) -> List[Anomaly]:
        """
        Check message for security anomalies.

        Args:
            message: Message to check

        Returns:
            List of detected anomalies

        Example:
            >>> validator = SecurityValidator()
            >>> anomalies = validator.check_anomalies(message)
            >>> for anomaly in anomalies:
            ...     print(f"Security Alert: {anomaly}")
        """
        anomalies = []

        # Check for various anomaly types
        anomalies.extend(self._check_replay_attack(message))
        anomalies.extend(self._check_timing_anomalies(message))
        anomalies.extend(self._check_malformed_patterns(message))
        anomalies.extend(self._check_injection_indicators(message))
        anomalies.extend(self._check_statistical_anomalies(message))

        # Store for historical analysis
        self.anomalies_detected.extend(anomalies)
        self.message_history.append(message)

        return anomalies

    def _check_replay_attack(self, message: Message) -> List[Anomaly]:
        """Detect potential replay attacks."""
        anomalies = []

        # Check for exact duplicates
        for historical_msg in self.message_history[-100:]:
            if self._messages_similar(message, historical_msg, threshold=0.95):
                anomalies.append(Anomaly(
                    anomaly_type="replay_attack",
                    severity=Severity.MEDIUM,
                    description="Message appears to be replayed from recent history",
                    confidence=0.7,
                    indicators=["exact_duplicate", "recent_occurrence"]
                ))
                break

        return anomalies

    def _check_timing_anomalies(self, message: Message) -> List[Anomaly]:
        """Detect timing-based anomalies."""
        anomalies = []

        # Check response time
        response_time = message.get_response_time()
        if response_time:
            if response_time < TimingConstants.RESPONSE_TIME_MIN:
                anomalies.append(Anomaly(
                    anomaly_type="timing_violation",
                    severity=Severity.HIGH,
                    description=f"Response time too short: {response_time} μs (min: {TimingConstants.RESPONSE_TIME_MIN} μs)",
                    confidence=1.0,
                    indicators=["response_too_early", "timing_violation"]
                ))
            elif response_time > TimingConstants.RESPONSE_TIME_MAX:
                anomalies.append(Anomaly(
                    anomaly_type="timing_violation",
                    severity=Severity.HIGH,
                    description=f"Response time too long: {response_time} μs (max: {TimingConstants.RESPONSE_TIME_MAX} μs)",
                    confidence=1.0,
                    indicators=["response_too_late", "timing_violation"]
                ))

        # Check inter-message gap
        if message.gap_time and message.gap_time < TimingConstants.INTER_MESSAGE_GAP_MIN:
            anomalies.append(Anomaly(
                anomaly_type="timing_violation",
                severity=Severity.MEDIUM,
                description=f"Inter-message gap too short: {message.gap_time} μs (min: {TimingConstants.INTER_MESSAGE_GAP_MIN} μs)",
                confidence=1.0,
                indicators=["insufficient_gap", "potential_flood"]
            ))

        return anomalies

    def _check_malformed_patterns(self, message: Message) -> List[Anomaly]:
        """Detect malformed packet patterns."""
        anomalies = []

        # Check for parity errors
        for word in (message.command_words + message.status_words + message.data_words):
            if not word.is_valid_parity():
                anomalies.append(Anomaly(
                    anomaly_type="malformed_packet",
                    severity=Severity.HIGH,
                    description="Word with invalid parity detected",
                    confidence=1.0,
                    indicators=["parity_error", "potential_corruption"]
                ))
                break

        # Check for address mismatches
        if message.command_words and message.status_words:
            cmd_addr = message.command_words[0].rt_address
            status_addr = message.status_words[0].rt_address
            if cmd_addr != status_addr:
                anomalies.append(Anomaly(
                    anomaly_type="malformed_packet",
                    severity=Severity.HIGH,
                    description=f"RT address mismatch: command={cmd_addr}, status={status_addr}",
                    confidence=0.9,
                    indicators=["address_mismatch", "potential_spoofing"]
                ))

        # Check for word count mismatches
        if message.command_words:
            cmd = message.command_words[0]
            if not cmd.is_mode_command:
                declared_count = cmd.actual_word_count
                actual_count = len(message.data_words)
                if declared_count != actual_count:
                    anomalies.append(Anomaly(
                        anomaly_type="malformed_packet",
                        severity=Severity.MEDIUM,
                        description=f"Word count mismatch: declared={declared_count}, actual={actual_count}",
                        confidence=1.0,
                        indicators=["word_count_mismatch", "potential_fuzzing"]
                    ))

        return anomalies

    def _check_injection_indicators(self, message: Message) -> List[Anomaly]:
        """Detect command injection indicators."""
        anomalies = []

        # Check for broadcast with status (illegal)
        if message.command_words:
            cmd = message.command_words[0]
            if cmd.rt_address == BROADCAST_ADDRESS and message.status_words:
                anomalies.append(Anomaly(
                    anomaly_type="injection_attack",
                    severity=Severity.HIGH,
                    description="Broadcast message with status response (illegal)",
                    confidence=0.9,
                    indicators=["broadcast_violation", "potential_injection"]
                ))

        # Check for suspicious status flags
        for status in message.status_words:
            if status.reserved != 0:
                anomalies.append(Anomaly(
                    anomaly_type="malformed_packet",
                    severity=Severity.LOW,
                    description=f"Reserved bits set in status word: {status.reserved:#05b}",
                    confidence=0.6,
                    indicators=["reserved_bits_set", "potential_manipulation"]
                ))

        return anomalies

    def _check_statistical_anomalies(self, message: Message) -> List[Anomaly]:
        """Detect statistical anomalies based on historical data."""
        anomalies = []

        # Check message rate (simplified)
        if len(self.message_history) > 100:
            recent_rate = len(self.message_history[-100:])
            if recent_rate > 90:  # More than 90 messages in last 100 time units
                anomalies.append(Anomaly(
                    anomaly_type="dos_attack",
                    severity=Severity.MEDIUM,
                    description="Abnormally high message rate detected",
                    confidence=0.7,
                    indicators=["high_rate", "potential_flood"]
                ))

        return anomalies

    def _messages_similar(self, msg1: Message, msg2: Message, threshold: float = 0.9) -> bool:
        """
        Check if two messages are similar.

        Args:
            msg1: First message
            msg2: Second message
            threshold: Similarity threshold (0.0-1.0)

        Returns:
            True if messages are similar above threshold
        """
        # Simple similarity check
        if msg1.message_type != msg2.message_type:
            return False

        if len(msg1.data_words) != len(msg2.data_words):
            return False

        # Check data word payloads
        matches = 0
        total = len(msg1.data_words)

        if total == 0:
            return True  # Both have no data words

        for d1, d2 in zip(msg1.data_words, msg2.data_words):
            if d1.payload == d2.payload:
                matches += 1

        similarity = matches / total
        return similarity >= threshold

    def detect_attack_pattern(self, messages: List[Message]) -> Optional[str]:
        """
        Analyze sequence of messages for known attack patterns.

        Args:
            messages: List of messages to analyze

        Returns:
            Attack type if detected, None otherwise

        Known Patterns:
        - Replay attack: Repeated messages
        - Flood attack: High message rate
        - Injection attack: Unauthorized commands
        - Fuzzing: Random malformed packets
        """
        if not messages:
            return None

        # Check for flooding (high rate of messages)
        if len(messages) > 50:
            return "potential_flood_attack"

        # Check for repeated messages (replay)
        unique_messages = set()
        for msg in messages:
            msg_sig = self._get_message_signature(msg)
            if msg_sig in unique_messages:
                return "potential_replay_attack"
            unique_messages.add(msg_sig)

        # Check for malformed patterns (fuzzing)
        malformed_count = 0
        for msg in messages:
            anomalies = self.check_anomalies(msg)
            if any(a.anomaly_type == "malformed_packet" for a in anomalies):
                malformed_count += 1

        if malformed_count > len(messages) * 0.3:  # > 30% malformed
            return "potential_fuzzing_attack"

        return None

    def _get_message_signature(self, message: Message) -> str:
        """Generate signature for message comparison."""
        # Simple signature based on message type and data
        data_sig = ",".join(str(d.payload) for d in message.data_words[:3])  # First 3 words
        return f"{message.message_type.value}:{data_sig}"

    def get_statistics(self) -> Dict[str, Any]:
        """Get security validation statistics."""
        anomaly_types = {}
        for anomaly in self.anomalies_detected:
            anomaly_types[anomaly.anomaly_type] = anomaly_types.get(anomaly.anomaly_type, 0) + 1

        return {
            'total_anomalies': len(self.anomalies_detected),
            'messages_analyzed': len(self.message_history),
            'anomaly_rate': (len(self.anomalies_detected) / len(self.message_history)) * 100 if self.message_history else 0,
            'anomaly_types': anomaly_types
        }
