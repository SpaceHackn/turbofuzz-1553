"""
MIL-STD-1553B Exception Hierarchy

This module defines all custom exceptions used throughout the packet engine.
The hierarchy allows for fine-grained exception handling while also supporting
catching broad categories of errors.
"""


class MIL1553Exception(Exception):
    """
    Base exception for all MIL-STD-1553B related errors.

    All custom exceptions in this package inherit from this class,
    allowing users to catch all package-specific errors with a single handler.
    """
    pass


# ============================================================================
# Protocol Exceptions
# ============================================================================

class ProtocolException(MIL1553Exception):
    """
    Base exception for protocol-related errors.

    Raised when protocol rules or specifications are violated.
    """
    pass


class ParityException(ProtocolException):
    """
    Raised when parity validation fails.

    This exception indicates that a word's parity bit does not match
    the calculated odd parity for the data field.
    """
    pass


class SyncException(ProtocolException):
    """
    Raised when sync pattern errors are detected.

    This can occur when:
    - Sync pattern is invalid (not 0b000 or 0b100)
    - Sync pattern doesn't match expected word type
    - Sync pattern cannot be detected in a bitstream
    """
    pass


class AddressException(ProtocolException):
    """
    Raised when RT address validation fails.

    This can occur when:
    - Address is out of valid range (0-31)
    - Address is used inappropriately for message type
    - Address conflicts exist
    """
    pass


class SubaddressException(ProtocolException):
    """
    Raised when subaddress validation fails.

    This can occur when:
    - Subaddress is out of valid range (0-31)
    - Mode command subaddress is used incorrectly
    - Subaddress is invalid for the operation
    """
    pass


class WordCountException(ProtocolException):
    """
    Raised when word count validation fails.

    This can occur when:
    - Declared word count doesn't match actual data words
    - Word count is out of valid range
    - Word count is incompatible with message type
    """
    pass


class MessageStructureException(ProtocolException):
    """
    Raised when message structure is invalid.

    This can occur when:
    - Required words are missing (e.g., missing status word)
    - Words appear in wrong order
    - Message type doesn't match word composition
    - Invalid combination of command/status/data words
    """
    pass


class TimingException(ProtocolException):
    """
    Raised when timing requirements are violated.

    This can occur when:
    - RT response time is outside valid range (4-12 μs)
    - Inter-message gap is insufficient (< 4 μs)
    - Bus timing constraints are violated
    """
    pass


class ModeCommandException(ProtocolException):
    """
    Raised when mode command validation fails.

    This can occur when:
    - Invalid mode code is used
    - Mode command structure is incorrect
    - Mode command is not supported by RT
    - Mode command used with invalid subaddress
    """
    pass


# ============================================================================
# Encoding/Decoding Exceptions
# ============================================================================

class EncodingException(MIL1553Exception):
    """
    Base exception for encoding and decoding errors.

    Raised when errors occur during Manchester encoding/decoding
    or bit-level operations.
    """
    pass


class ManchesterEncodingException(EncodingException):
    """
    Raised when Manchester II encoding/decoding fails.

    This can occur when:
    - Invalid Manchester transitions are detected
    - Bitstream cannot be decoded
    - Encoding produces invalid output
    """
    pass


class BitStreamException(EncodingException):
    """
    Raised when bitstream operations fail.

    This can occur when:
    - Insufficient bits available for operation
    - Bitstream format is invalid
    - Bit alignment errors
    """
    pass


class DecodingException(EncodingException):
    """
    Raised when decoding wire format fails.

    This can occur when:
    - Cannot parse word from bitstream
    - Invalid word structure detected
    - Corrupted data prevents decoding
    """
    pass


# ============================================================================
# Device Exceptions
# ============================================================================

class DeviceException(MIL1553Exception):
    """
    Base exception for device operation errors.

    Raised when BC, RT, or BM operations fail.
    """
    pass


class BusControllerException(DeviceException):
    """
    Raised when Bus Controller operations fail.

    This can occur when:
    - Invalid command scheduling
    - RT communication errors
    - Bus arbitration issues
    """
    pass


class RemoteTerminalException(DeviceException):
    """
    Raised when Remote Terminal operations fail.

    This can occur when:
    - RT cannot process command
    - Subaddress handler not found
    - RT is busy or in error state
    - Invalid mode command received
    """
    pass


class BusMonitorException(DeviceException):
    """
    Raised when Bus Monitor operations fail.

    This can occur when:
    - Capture buffer overflow
    - Filter configuration errors
    - Analysis failures
    """
    pass


class DeviceBusyException(DeviceException):
    """
    Raised when a device is busy and cannot process a request.

    This is a normal protocol condition but represented as an exception
    for flow control purposes.
    """
    pass


class DeviceNotReadyException(DeviceException):
    """
    Raised when a device is not ready for operations.

    This can occur when:
    - Device not initialized
    - Device in reset state
    - Device configuration incomplete
    """
    pass


# ============================================================================
# Security Testing Exceptions
# ============================================================================

class SecurityException(MIL1553Exception):
    """
    Base exception for security testing related errors.

    Raised when security testing operations encounter errors.
    """
    pass


class FuzzingException(SecurityException):
    """
    Raised when fuzzing operations fail.

    This can occur when:
    - Fuzzing strategy cannot be applied
    - Mutation constraints violated
    - Fuzzer configuration invalid
    """
    pass


class AttackException(SecurityException):
    """
    Raised when attack execution fails.

    This can occur when:
    - Attack prerequisites not met
    - Attack parameters invalid
    - Attack cannot be executed on target
    """
    pass


class InjectionException(AttackException):
    """
    Raised when injection attack fails.

    This can occur when:
    - Cannot inject into bus timing
    - Injection conflicts with existing traffic
    - Invalid injection parameters
    """
    pass


class ReplayException(AttackException):
    """
    Raised when replay attack fails.

    This can occur when:
    - No captured messages to replay
    - Replay timing cannot be satisfied
    - Replay modification invalid
    """
    pass


class ValidationException(SecurityException):
    """
    Raised when validation operations fail.

    This can occur when:
    - Validator configuration invalid
    - Validation logic errors
    - Cannot complete validation checks
    """
    pass


# ============================================================================
# Configuration Exceptions
# ============================================================================

class ConfigurationException(MIL1553Exception):
    """
    Raised when configuration errors occur.

    This can occur when:
    - Invalid configuration parameters
    - Configuration file cannot be loaded
    - Configuration conflicts detected
    """
    pass


# ============================================================================
# Data/Value Exceptions
# ============================================================================

class InvalidValueException(MIL1553Exception):
    """
    Raised when an invalid value is provided.

    This is a generic exception for value validation failures
    that don't fit other specific categories.
    """
    pass


class OutOfRangeException(InvalidValueException):
    """
    Raised when a value is out of valid range.

    This can occur when:
    - Numeric value exceeds field width
    - Value outside protocol limits
    - Index out of bounds
    """
    pass


# ============================================================================
# Helper Functions
# ============================================================================

def create_protocol_exception(error_type: str, message: str, **kwargs) -> ProtocolException:
    """
    Factory function to create appropriate protocol exception based on error type.

    Args:
        error_type: Type of protocol error (from ErrorType enum)
        message: Error message
        **kwargs: Additional context for the exception

    Returns:
        Appropriate ProtocolException subclass instance
    """
    exception_map = {
        "parity_error": ParityException,
        "invalid_sync": SyncException,
        "invalid_address": AddressException,
        "invalid_subaddress": SubaddressException,
        "word_count_mismatch": WordCountException,
        "timing_violation": TimingException,
        "response_too_early": TimingException,
        "response_too_late": TimingException,
        "insufficient_gap": TimingException,
        "protocol_violation": MessageStructureException,
        "invalid_message_type": MessageStructureException,
        "missing_status_word": MessageStructureException,
        "missing_data_words": MessageStructureException,
    }

    exception_class = exception_map.get(error_type, ProtocolException)
    return exception_class(message)
