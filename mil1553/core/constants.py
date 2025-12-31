"""
MIL-STD-1553B Protocol Constants

This module defines all constants, enums, bit masks, and timing parameters
for the MIL-STD-1553B protocol implementation.
"""

from enum import Enum, IntEnum


# ============================================================================
# Sync Patterns
# ============================================================================

class SyncPattern(IntEnum):
    """
    3-bit sync patterns for MIL-STD-1553B words.

    Sync patterns are mutually exclusive - a valid command/status sync
    is an invalid data sync and vice versa.
    """
    COMMAND_STATUS = 0b100  # Used for Command and Status words
    DATA = 0b000            # Used for Data words


# ============================================================================
# Message Types
# ============================================================================

class MessageType(Enum):
    """Types of messages in MIL-STD-1553B protocol."""
    BC_TO_RT = "bc_to_rt"          # Bus Controller to Remote Terminal
    RT_TO_BC = "rt_to_bc"          # Remote Terminal to Bus Controller
    RT_TO_RT = "rt_to_rt"          # Remote Terminal to Remote Terminal
    MODE_COMMAND = "mode_command"  # Mode command (no data or limited data)
    BROADCAST = "broadcast"        # Broadcast message (RT address = 31)


# ============================================================================
# Mode Codes
# ============================================================================

class ModeCode(IntEnum):
    """
    Mode command codes (5-bit values when subaddress = 0 or 31).

    Mode commands are special commands that control RT behavior rather than
    transferring data.
    """
    # Mode commands without data (subaddress = 0 or 31, T/R = 0)
    DYNAMIC_BUS_CONTROL = 0b00000
    SYNCHRONIZE = 0b00001
    TRANSMIT_STATUS_WORD = 0b00010
    INITIATE_SELF_TEST = 0b00011
    TRANSMITTER_SHUTDOWN = 0b00100
    OVERRIDE_TRANSMITTER_SHUTDOWN = 0b00101
    INHIBIT_TERMINAL_FLAG = 0b00110
    OVERRIDE_INHIBIT_TERMINAL_FLAG = 0b00111
    RESET_REMOTE_TERMINAL = 0b01000

    # Mode commands with data (subaddress = 0 or 31, T/R = 1)
    TRANSMIT_VECTOR_WORD = 0b10000
    SYNCHRONIZE_WITH_DATA = 0b10001
    TRANSMIT_LAST_COMMAND = 0b10010
    TRANSMIT_BIT_WORD = 0b10011

    # Reserved mode codes (0b01001-0b01111, 0b10100-0b11111)
    # These are not defined by the standard but can be used for testing


# ============================================================================
# Timing Constants
# ============================================================================

class TimingConstants:
    """
    MIL-STD-1553B timing parameters in microseconds.

    These timing values are critical for protocol compliance and
    can be violated for security testing purposes.
    """
    # Bit and word timing
    BIT_TIME = 1.0                    # 1 MHz bit rate = 1 μs per bit
    WORD_TIME = 20.0                  # 20 bits per word = 20 μs

    # Response timing
    RESPONSE_TIME_MIN = 4.0           # Minimum RT response time (4 μs)
    RESPONSE_TIME_MAX = 12.0          # Maximum RT response time (12 μs)
    RESPONSE_TIME_TYPICAL = 8.0       # Typical RT response time

    # Inter-message timing
    INTER_MESSAGE_GAP_MIN = 4.0       # Minimum gap between messages (4 μs)
    INTER_MESSAGE_GAP_TYPICAL = 20.0  # Typical gap between messages

    # Sync pulse timing
    SYNC_PULSE_WIDTH = 1.5            # Sync pulse width (1.5 μs)

    # Manchester encoding
    MANCHESTER_BIT_TIME = 0.5         # Half-bit time for Manchester (0.5 μs)
    MANCHESTER_CLOCK_RATE = 2.0       # 2 MHz for Manchester encoding (2x bit rate)


# ============================================================================
# Bit Masks and Positions
# ============================================================================

class BitMasks:
    """
    Bit masks for extracting fields from 20-bit words.

    Word structure: [sync:3][data:16][parity:1]
    Total: 20 bits
    """
    # Full word mask
    WORD_MASK = 0xFFFFF               # 20 bits: 0b11111111111111111111

    # Sync pattern (bits 19-17)
    SYNC_MASK = 0xE0000               # 0b11100000000000000000
    SYNC_SHIFT = 17

    # Data field (bits 16-1)
    DATA_MASK = 0x1FFFE               # 0b00011111111111111110
    DATA_SHIFT = 1

    # Parity bit (bit 0)
    PARITY_MASK = 0x00001             # 0b00000000000000000001
    PARITY_SHIFT = 0

    # Command Word field masks (within 16-bit data field)
    # Command word data layout: [RT_addr:5][T/R:1][subaddr:5][word_count:5]
    RT_ADDRESS_MASK = 0xF800          # bits 15-11: 0b1111100000000000
    RT_ADDRESS_SHIFT = 11

    TR_BIT_MASK = 0x0400              # bit 10: 0b0000010000000000
    TR_BIT_SHIFT = 10

    SUBADDRESS_MASK = 0x03E0          # bits 9-5: 0b0000001111100000
    SUBADDRESS_SHIFT = 5

    WORD_COUNT_MODE_MASK = 0x001F     # bits 4-0: 0b0000000000011111
    WORD_COUNT_MODE_SHIFT = 0

    # Status Word field masks (within 16-bit data field)
    # Status word data layout: [RT_addr:5][flags:10]
    # Flags: [ME][INST][SR][RSV:3][BCR][BUSY][SSF][DBC][TF]
    STATUS_RT_ADDRESS_MASK = 0xF800   # bits 15-11
    STATUS_RT_ADDRESS_SHIFT = 11

    MESSAGE_ERROR_MASK = 0x0400       # bit 10
    MESSAGE_ERROR_SHIFT = 10

    INSTRUMENTATION_MASK = 0x0200     # bit 9
    INSTRUMENTATION_SHIFT = 9

    SERVICE_REQUEST_MASK = 0x0100     # bit 8
    SERVICE_REQUEST_SHIFT = 8

    RESERVED_MASK = 0x00E0            # bits 7-5 (3 bits reserved)
    RESERVED_SHIFT = 5

    BROADCAST_RECEIVED_MASK = 0x0010  # bit 4
    BROADCAST_RECEIVED_SHIFT = 4

    BUSY_MASK = 0x0008                # bit 3
    BUSY_SHIFT = 3

    SUBSYSTEM_FLAG_MASK = 0x0004      # bit 2
    SUBSYSTEM_FLAG_SHIFT = 2

    DYNAMIC_BUS_CONTROL_MASK = 0x0002 # bit 1
    DYNAMIC_BUS_CONTROL_SHIFT = 1

    TERMINAL_FLAG_MASK = 0x0001       # bit 0
    TERMINAL_FLAG_SHIFT = 0


# ============================================================================
# Protocol Limits
# ============================================================================

# Address limits
MAX_RT_ADDRESS = 30                   # Valid RT addresses: 0-30
BROADCAST_ADDRESS = 31                # Broadcast address
MIN_RT_ADDRESS = 0                    # Minimum RT address

# Subaddress limits
MIN_SUBADDRESS = 0                    # Minimum subaddress
MAX_SUBADDRESS = 31                   # Maximum subaddress
MODE_COMMAND_SUBADDRESS_LOW = 0       # Subaddress 0 indicates mode command
MODE_COMMAND_SUBADDRESS_HIGH = 31     # Subaddress 31 indicates mode command

# Word count limits
MIN_WORD_COUNT = 0                    # 0 represents 32 words
MAX_WORD_COUNT = 31                   # Maximum word count value
ACTUAL_MAX_DATA_WORDS = 32            # Actual maximum data words (when count = 0)

# Bit widths
SYNC_BITS = 3
DATA_BITS = 16
PARITY_BITS = 1
TOTAL_WORD_BITS = 20                  # sync + data + parity

RT_ADDRESS_BITS = 5
TR_BIT_BITS = 1
SUBADDRESS_BITS = 5
WORD_COUNT_BITS = 5


# ============================================================================
# Error Types
# ============================================================================

class ErrorType(Enum):
    """
    Types of errors that can occur or be injected for security testing.
    """
    # Protocol errors
    PARITY_ERROR = "parity_error"
    INVALID_SYNC = "invalid_sync"
    INVALID_ADDRESS = "invalid_address"
    INVALID_SUBADDRESS = "invalid_subaddress"
    WORD_COUNT_MISMATCH = "word_count_mismatch"

    # Timing errors
    TIMING_VIOLATION = "timing_violation"
    RESPONSE_TOO_EARLY = "response_too_early"
    RESPONSE_TOO_LATE = "response_too_late"
    INSUFFICIENT_GAP = "insufficient_gap"

    # Encoding errors
    MANCHESTER_ERROR = "manchester_error"
    ENCODING_VIOLATION = "encoding_violation"

    # Message structure errors
    PROTOCOL_VIOLATION = "protocol_violation"
    INVALID_MESSAGE_TYPE = "invalid_message_type"
    MISSING_STATUS_WORD = "missing_status_word"
    MISSING_DATA_WORDS = "missing_data_words"

    # Status word errors
    MESSAGE_ERROR_FLAG = "message_error_flag"
    BUSY_FLAG = "busy_flag"
    TERMINAL_FLAG = "terminal_flag"


# ============================================================================
# Transmit/Receive Bit Values
# ============================================================================

class TransmitReceive(IntEnum):
    """T/R bit values in command word."""
    RECEIVE = 0  # BC commanding RT to receive data
    TRANSMIT = 1 # BC commanding RT to transmit data


# ============================================================================
# Word Types
# ============================================================================

class WordType(Enum):
    """Types of words in MIL-STD-1553B protocol."""
    COMMAND = "command"
    STATUS = "status"
    DATA = "data"


# ============================================================================
# Severity Levels
# ============================================================================

class Severity(Enum):
    """Severity levels for violations and security findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# Helper Functions
# ============================================================================

def is_mode_command_subaddress(subaddress: int) -> bool:
    """
    Check if a subaddress indicates a mode command.

    Args:
        subaddress: 5-bit subaddress value

    Returns:
        True if subaddress is 0 or 31 (mode command indicators)
    """
    return subaddress == MODE_COMMAND_SUBADDRESS_LOW or subaddress == MODE_COMMAND_SUBADDRESS_HIGH


def is_broadcast_address(address: int) -> bool:
    """
    Check if an RT address is the broadcast address.

    Args:
        address: 5-bit RT address value

    Returns:
        True if address is 31 (broadcast)
    """
    return address == BROADCAST_ADDRESS


def is_valid_rt_address(address: int) -> bool:
    """
    Check if an RT address is valid.

    Args:
        address: 5-bit RT address value

    Returns:
        True if address is in range 0-31
    """
    return MIN_RT_ADDRESS <= address <= BROADCAST_ADDRESS


def word_count_to_actual(word_count: int) -> int:
    """
    Convert word count field value to actual number of data words.

    In MIL-STD-1553B, a word count of 0 represents 32 words.

    Args:
        word_count: 5-bit word count value (0-31)

    Returns:
        Actual number of data words (1-32)
    """
    return 32 if word_count == 0 else word_count


def actual_to_word_count(actual: int) -> int:
    """
    Convert actual number of data words to word count field value.

    Args:
        actual: Actual number of data words (1-32)

    Returns:
        Word count field value (0-31)
    """
    if actual == 32:
        return 0
    elif 1 <= actual <= 31:
        return actual
    else:
        raise ValueError(f"Invalid actual word count: {actual}. Must be 1-32.")
