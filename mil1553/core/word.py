"""
MIL-STD-1553B Word Classes

This module implements the core Word classes for MIL-STD-1553B protocol:
- Word: Base class for all 20-bit words
- CommandWord: Command word with RT address, T/R, subaddress, word count
- StatusWord: Status word with RT address and status flags
- DataWord: Data word with 16-bit payload

Word structure: [sync:3 bits][data:16 bits][parity:1 bit] = 20 bits total
"""

from typing import Optional, Union
from abc import ABC, abstractmethod
import time

from mil1553.core.constants import (
    SyncPattern, WordType, MessageType, ModeCode, TransmitReceive,
    BitMasks, BROADCAST_ADDRESS, MAX_RT_ADDRESS, MIN_RT_ADDRESS,
    MAX_SUBADDRESS, MIN_SUBADDRESS, MAX_WORD_COUNT,
    is_mode_command_subaddress, is_broadcast_address, is_valid_rt_address,
    word_count_to_actual, actual_to_word_count
)
from mil1553.core.exceptions import (
    ParityException, SyncException, AddressException, SubaddressException,
    WordCountException, InvalidValueException
)
from mil1553.utils.bitops import extract_bits, set_bits, to_binary_string, to_hex_string
from mil1553.utils.parity import (
    calculate_word_parity_1553, verify_word_parity_1553, corrupt_parity
)


class Word(ABC):
    """
    Base class for all MIL-STD-1553B 20-bit words.

    Structure: [sync:3][data:16][parity:1] = 20 bits

    Attributes:
        sync: 3-bit sync pattern (SyncPattern enum)
        data: 16-bit data field
        parity: 1-bit parity (odd parity over sync + data)
        timestamp: Optional timestamp (seconds since epoch)
        _raw_value: Complete 20-bit word value
    """

    def __init__(self, sync: int, data: int, parity: Optional[int] = None, timestamp: Optional[float] = None):
        """
        Initialize a Word.

        Args:
            sync: 3-bit sync pattern
            data: 16-bit data field
            parity: Optional parity bit (calculated if None)
            timestamp: Optional timestamp
        """
        self.sync = sync & 0x7  # 3 bits
        self.data = data & 0xFFFF  # 16 bits
        self.timestamp = timestamp if timestamp is not None else time.time()

        # Calculate parity if not provided
        if parity is None:
            self.parity = calculate_word_parity_1553(self.sync, self.data)
        else:
            self.parity = parity & 0x1

        # Construct raw 20-bit value
        self._update_raw_value()

    def _update_raw_value(self):
        """Update the internal raw 20-bit word value."""
        self._raw_value = (self.sync << 17) | (self.data << 1) | self.parity

    @property
    def raw_value(self) -> int:
        """Get the complete 20-bit word value."""
        return self._raw_value

    def calculate_parity(self) -> int:
        """
        Calculate the correct parity bit for current sync and data.

        Returns:
            Parity bit (0 or 1)
        """
        return calculate_word_parity_1553(self.sync, self.data)

    def is_valid_parity(self) -> bool:
        """
        Check if the parity bit is correct.

        Returns:
            True if parity is valid
        """
        return verify_word_parity_1553(self.sync, self.data, self.parity)

    def validate(self) -> bool:
        """
        Validate the word structure.

        Returns:
            True if word is valid

        Raises:
            ParityException: If parity is invalid
            SyncException: If sync pattern is invalid
        """
        # Check parity
        if not self.is_valid_parity():
            raise ParityException(
                f"Invalid parity: expected {self.calculate_parity()}, got {self.parity}"
            )

        # Check sync pattern (must be valid for word type)
        if not self._is_valid_sync():
            raise SyncException(
                f"Invalid sync pattern for {self.__class__.__name__}: {self.sync:#05b}"
            )

        return True

    @abstractmethod
    def _is_valid_sync(self) -> bool:
        """Check if sync pattern is valid for this word type."""
        pass

    def corrupt_parity(self) -> 'Word':
        """
        Create a copy of this word with corrupted (flipped) parity.

        Useful for security testing.

        Returns:
            New word instance with corrupted parity
        """
        corrupted = self.__class__.__new__(self.__class__)
        corrupted.__dict__.update(self.__dict__)
        corrupted.parity = 1 - self.parity
        corrupted._update_raw_value()
        return corrupted

    def corrupt_sync(self, new_sync: Optional[int] = None) -> 'Word':
        """
        Create a copy of this word with corrupted sync pattern.

        Args:
            new_sync: New sync pattern (random invalid if None)

        Returns:
            New word instance with corrupted sync
        """
        corrupted = self.__class__.__new__(self.__class__)
        corrupted.__dict__.update(self.__dict__)

        if new_sync is None:
            # Flip to opposite sync type
            if self.sync == SyncPattern.COMMAND_STATUS:
                corrupted.sync = SyncPattern.DATA
            else:
                corrupted.sync = SyncPattern.COMMAND_STATUS
        else:
            corrupted.sync = new_sync & 0x7

        corrupted._update_raw_value()
        return corrupted

    def to_bytes(self) -> bytes:
        """
        Convert word to bytes (big-endian, 3 bytes for 20 bits).

        Returns:
            3-byte representation
        """
        # Pack 20 bits into 3 bytes
        return self._raw_value.to_bytes(3, byteorder='big')

    def to_hex(self) -> str:
        """
        Convert word to hexadecimal string.

        Returns:
            Hex string (5 hex digits for 20 bits)
        """
        return to_hex_string(self._raw_value, 20)

    def to_binary_string(self, separator: str = "") -> str:
        """
        Convert word to binary string.

        Args:
            separator: Optional separator between nibbles

        Returns:
            Binary string representation
        """
        return to_binary_string(self._raw_value, 20, separator)

    @classmethod
    def from_raw(cls, raw: int, timestamp: Optional[float] = None) -> 'Word':
        """
        Create word from raw 20-bit value.

        Args:
            raw: 20-bit word value
            timestamp: Optional timestamp

        Returns:
            Word instance
        """
        sync = (raw >> 17) & 0x7
        data = (raw >> 1) & 0xFFFF
        parity = raw & 0x1
        return cls._from_parts(sync, data, parity, timestamp)

    @classmethod
    @abstractmethod
    def _from_parts(cls, sync: int, data: int, parity: int, timestamp: Optional[float]) -> 'Word':
        """Create word from individual parts (implemented by subclasses)."""
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(sync={self.sync:#05b}, data={self.data:#06x}, parity={self.parity})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Word):
            return False
        return self._raw_value == other._raw_value

    def __hash__(self) -> int:
        return hash(self._raw_value)


class CommandWord(Word):
    """
    Command Word for MIL-STD-1553B.

    Structure: [sync:3][RT_addr:5][T/R:1][subaddr:5][word_count:5][parity:1]

    The command word is issued by the Bus Controller to control Remote Terminals.
    """

    def __init__(
        self,
        rt_address: int,
        transmit_receive: int,
        subaddress: int,
        word_count: int,
        parity: Optional[int] = None,
        timestamp: Optional[float] = None
    ):
        """
        Initialize a Command Word.

        Args:
            rt_address: 5-bit RT address (0-31, 31 is broadcast)
            transmit_receive: T/R bit (0=receive, 1=transmit)
            subaddress: 5-bit subaddress (0-31, 0 and 31 indicate mode commands)
            word_count: 5-bit word count or mode code (0 represents 32 words)
            parity: Optional parity bit
            timestamp: Optional timestamp
        """
        # Validate inputs
        if not is_valid_rt_address(rt_address):
            raise AddressException(f"Invalid RT address: {rt_address}. Must be 0-31.")

        if not (MIN_SUBADDRESS <= subaddress <= MAX_SUBADDRESS):
            raise SubaddressException(f"Invalid subaddress: {subaddress}. Must be 0-31.")

        if not (0 <= word_count <= MAX_WORD_COUNT):
            raise WordCountException(f"Invalid word count: {word_count}. Must be 0-31.")

        if transmit_receive not in (0, 1):
            raise InvalidValueException(f"Invalid T/R bit: {transmit_receive}. Must be 0 or 1.")

        # Store field values
        self.rt_address = rt_address
        self.transmit_receive = transmit_receive
        self.subaddress = subaddress
        self.word_count_mode = word_count

        # Pack into 16-bit data field
        data = (
            (rt_address << BitMasks.RT_ADDRESS_SHIFT) |
            (transmit_receive << BitMasks.TR_BIT_SHIFT) |
            (subaddress << BitMasks.SUBADDRESS_SHIFT) |
            word_count
        )

        # Initialize base Word with command/status sync
        super().__init__(SyncPattern.COMMAND_STATUS, data, parity, timestamp)

    @property
    def is_mode_command(self) -> bool:
        """Check if this is a mode command (subaddress 0 or 31)."""
        return is_mode_command_subaddress(self.subaddress)

    @property
    def is_broadcast(self) -> bool:
        """Check if this is a broadcast command (RT address 31)."""
        return is_broadcast_address(self.rt_address)

    @property
    def actual_word_count(self) -> int:
        """Get actual number of data words (converts 0 to 32)."""
        if self.is_mode_command:
            return 0  # Mode commands have special handling
        return word_count_to_actual(self.word_count_mode)

    @property
    def mode_code(self) -> Optional[ModeCode]:
        """Get mode code if this is a mode command."""
        if not self.is_mode_command:
            return None
        try:
            return ModeCode(self.word_count_mode)
        except ValueError:
            return None  # Unknown/reserved mode code

    def _is_valid_sync(self) -> bool:
        """Command words must have COMMAND_STATUS sync."""
        return self.sync == SyncPattern.COMMAND_STATUS

    def get_message_type(self) -> MessageType:
        """
        Determine message type from command word.

        Returns:
            MessageType enum value
        """
        if self.is_broadcast:
            return MessageType.BROADCAST
        elif self.is_mode_command:
            return MessageType.MODE_COMMAND
        elif self.transmit_receive == TransmitReceive.RECEIVE:
            return MessageType.BC_TO_RT
        else:  # TRANSMIT
            return MessageType.RT_TO_BC

    @classmethod
    def _from_parts(cls, sync: int, data: int, parity: int, timestamp: Optional[float]) -> 'CommandWord':
        """Create CommandWord from raw parts."""
        rt_address = (data >> BitMasks.RT_ADDRESS_SHIFT) & 0x1F
        tr = (data >> BitMasks.TR_BIT_SHIFT) & 0x1
        subaddress = (data >> BitMasks.SUBADDRESS_SHIFT) & 0x1F
        word_count = data & 0x1F
        return cls(rt_address, tr, subaddress, word_count, parity, timestamp)

    def __repr__(self) -> str:
        mode_str = f", mode={self.mode_code.name}" if self.is_mode_command else ""
        return (
            f"CommandWord(RT={self.rt_address}, T/R={self.transmit_receive}, "
            f"SA={self.subaddress}, WC={self.word_count_mode}{mode_str})"
        )


class StatusWord(Word):
    """
    Status Word for MIL-STD-1553B.

    Structure: [sync:3][RT_addr:5][flags:10][parity:1]

    Flags (10 bits):
    - Message Error (bit 10)
    - Instrumentation (bit 9)
    - Service Request (bit 8)
    - Reserved (bits 7-5, 3 bits)
    - Broadcast Received (bit 4)
    - Busy (bit 3)
    - Subsystem Flag (bit 2)
    - Dynamic Bus Control (bit 1)
    - Terminal Flag (bit 0)
    """

    def __init__(
        self,
        rt_address: int,
        message_error: bool = False,
        instrumentation: bool = False,
        service_request: bool = False,
        reserved: int = 0,
        broadcast_received: bool = False,
        busy: bool = False,
        subsystem_flag: bool = False,
        dynamic_bus_control: bool = False,
        terminal_flag: bool = False,
        parity: Optional[int] = None,
        timestamp: Optional[float] = None
    ):
        """
        Initialize a Status Word.

        Args:
            rt_address: 5-bit RT address (0-30, broadcast is not valid for status)
            message_error: Message error flag
            instrumentation: Instrumentation flag
            service_request: Service request flag
            reserved: 3-bit reserved field (should be 0)
            broadcast_received: Broadcast received flag
            busy: Busy flag
            subsystem_flag: Subsystem flag
            dynamic_bus_control: Dynamic bus control acceptance flag
            terminal_flag: Terminal flag
            parity: Optional parity bit
            timestamp: Optional timestamp
        """
        # Validate RT address (broadcast not valid for status words from RT)
        if not (MIN_RT_ADDRESS <= rt_address <= MAX_RT_ADDRESS):
            raise AddressException(f"Invalid RT address for status word: {rt_address}")

        # Store field values
        self.rt_address = rt_address
        self.message_error = bool(message_error)
        self.instrumentation = bool(instrumentation)
        self.service_request = bool(service_request)
        self.reserved = reserved & 0x7  # 3 bits
        self.broadcast_received = bool(broadcast_received)
        self.busy = bool(busy)
        self.subsystem_flag = bool(subsystem_flag)
        self.dynamic_bus_control = bool(dynamic_bus_control)
        self.terminal_flag = bool(terminal_flag)

        # Pack into 16-bit data field
        data = (
            (rt_address << BitMasks.STATUS_RT_ADDRESS_SHIFT) |
            (int(message_error) << BitMasks.MESSAGE_ERROR_SHIFT) |
            (int(instrumentation) << BitMasks.INSTRUMENTATION_SHIFT) |
            (int(service_request) << BitMasks.SERVICE_REQUEST_SHIFT) |
            (reserved << BitMasks.RESERVED_SHIFT) |
            (int(broadcast_received) << BitMasks.BROADCAST_RECEIVED_SHIFT) |
            (int(busy) << BitMasks.BUSY_SHIFT) |
            (int(subsystem_flag) << BitMasks.SUBSYSTEM_FLAG_SHIFT) |
            (int(dynamic_bus_control) << BitMasks.DYNAMIC_BUS_CONTROL_SHIFT) |
            int(terminal_flag)
        )

        # Initialize base Word with command/status sync
        super().__init__(SyncPattern.COMMAND_STATUS, data, parity, timestamp)

    def _is_valid_sync(self) -> bool:
        """Status words must have COMMAND_STATUS sync."""
        return self.sync == SyncPattern.COMMAND_STATUS

    def get_active_flags(self) -> list[str]:
        """
        Get list of active (True) status flags.

        Returns:
            List of flag names that are set
        """
        flags = []
        if self.message_error:
            flags.append("MESSAGE_ERROR")
        if self.instrumentation:
            flags.append("INSTRUMENTATION")
        if self.service_request:
            flags.append("SERVICE_REQUEST")
        if self.broadcast_received:
            flags.append("BROADCAST_RECEIVED")
        if self.busy:
            flags.append("BUSY")
        if self.subsystem_flag:
            flags.append("SUBSYSTEM_FLAG")
        if self.dynamic_bus_control:
            flags.append("DYNAMIC_BUS_CONTROL")
        if self.terminal_flag:
            flags.append("TERMINAL_FLAG")
        return flags

    def clear_all_flags(self):
        """Clear all status flags (set to False)."""
        self.message_error = False
        self.instrumentation = False
        self.service_request = False
        self.broadcast_received = False
        self.busy = False
        self.subsystem_flag = False
        self.dynamic_bus_control = False
        self.terminal_flag = False
        self.reserved = 0

        # Rebuild data field
        self.data = self.rt_address << BitMasks.STATUS_RT_ADDRESS_SHIFT
        self.parity = self.calculate_parity()
        self._update_raw_value()

    @classmethod
    def _from_parts(cls, sync: int, data: int, parity: int, timestamp: Optional[float]) -> 'StatusWord':
        """Create StatusWord from raw parts."""
        rt_address = (data >> BitMasks.STATUS_RT_ADDRESS_SHIFT) & 0x1F
        message_error = bool((data >> BitMasks.MESSAGE_ERROR_SHIFT) & 1)
        instrumentation = bool((data >> BitMasks.INSTRUMENTATION_SHIFT) & 1)
        service_request = bool((data >> BitMasks.SERVICE_REQUEST_SHIFT) & 1)
        reserved = (data >> BitMasks.RESERVED_SHIFT) & 0x7
        broadcast_received = bool((data >> BitMasks.BROADCAST_RECEIVED_SHIFT) & 1)
        busy = bool((data >> BitMasks.BUSY_SHIFT) & 1)
        subsystem_flag = bool((data >> BitMasks.SUBSYSTEM_FLAG_SHIFT) & 1)
        dynamic_bus_control = bool((data >> BitMasks.DYNAMIC_BUS_CONTROL_SHIFT) & 1)
        terminal_flag = bool(data & 1)

        return cls(
            rt_address, message_error, instrumentation, service_request, reserved,
            broadcast_received, busy, subsystem_flag, dynamic_bus_control,
            terminal_flag, parity, timestamp
        )

    def __repr__(self) -> str:
        flags = self.get_active_flags()
        flags_str = f", flags={flags}" if flags else ""
        return f"StatusWord(RT={self.rt_address}{flags_str})"


class DataWord(Word):
    """
    Data Word for MIL-STD-1553B.

    Structure: [sync:3][data:16][parity:1]

    The data word carries the actual payload data in messages.
    """

    def __init__(self, payload: int, parity: Optional[int] = None, timestamp: Optional[float] = None):
        """
        Initialize a Data Word.

        Args:
            payload: 16-bit data payload
            parity: Optional parity bit
            timestamp: Optional timestamp
        """
        if not (0 <= payload <= 0xFFFF):
            raise InvalidValueException(f"Invalid payload: {payload}. Must be 16-bit (0-0xFFFF).")

        self.payload = payload & 0xFFFF

        # Initialize base Word with data sync
        super().__init__(SyncPattern.DATA, payload, parity, timestamp)

    def _is_valid_sync(self) -> bool:
        """Data words must have DATA sync."""
        return self.sync == SyncPattern.DATA

    def to_signed_int(self) -> int:
        """
        Interpret payload as signed 16-bit integer (two's complement).

        Returns:
            Signed integer value (-32768 to 32767)
        """
        if self.payload & 0x8000:  # Negative
            return self.payload - 0x10000
        return self.payload

    def to_unsigned_int(self) -> int:
        """
        Interpret payload as unsigned 16-bit integer.

        Returns:
            Unsigned integer value (0 to 65535)
        """
        return self.payload

    @classmethod
    def from_bytes(cls, data: bytes, parity: Optional[int] = None, timestamp: Optional[float] = None) -> 'DataWord':
        """
        Create DataWord from bytes.

        Args:
            data: 2-byte data (big-endian)
            parity: Optional parity bit
            timestamp: Optional timestamp

        Returns:
            DataWord instance
        """
        if len(data) != 2:
            raise InvalidValueException(f"Data must be exactly 2 bytes, got {len(data)}")

        payload = int.from_bytes(data, byteorder='big')
        return cls(payload, parity, timestamp)

    @classmethod
    def _from_parts(cls, sync: int, data: int, parity: int, timestamp: Optional[float]) -> 'DataWord':
        """Create DataWord from raw parts."""
        return cls(data, parity, timestamp)

    def __repr__(self) -> str:
        return f"DataWord(payload={self.payload:#06x})"
