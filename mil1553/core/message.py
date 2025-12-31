"""
MIL-STD-1553B Message Classes

This module implements message structures for MIL-STD-1553B protocol.
A message is a complete transaction consisting of command, status, and/or data words.

Message Types:
- BC-to-RT: Command + Data words
- RT-to-BC: Command + Status + Data words
- RT-to-RT: Command(rx) + Command(tx) + Status(rx) + Data + Status(tx)
- Mode Command: Command + Status (no data or limited data)
- Broadcast: Command(RT=31) + Data words
"""

from typing import List, Optional, Union, Dict, Any
import time

from mil1553.core.constants import (
    MessageType, TimingConstants, word_count_to_actual,
    TOTAL_WORD_BITS
)
from mil1553.core.word import Word, CommandWord, StatusWord, DataWord
from mil1553.core.exceptions import (
    MessageStructureException, WordCountException, InvalidValueException
)
from mil1553.core.encoding import ManchesterEncoder, SimpleBinaryEncoder


class Message:
    """
    Container for a complete MIL-STD-1553B message transaction.

    A message represents a complete bus transaction, which may include:
    - Command word(s)
    - Status word(s)
    - Data words
    - Timing information
    """

    def __init__(
        self,
        message_type: MessageType,
        command_word: Union[CommandWord, List[CommandWord]],
        status_word: Optional[Union[StatusWord, List[StatusWord]]] = None,
        data_words: Optional[List[DataWord]] = None,
        timestamp: Optional[float] = None,
        bus_id: str = 'A',
        gap_time: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a Message.

        Args:
            message_type: Type of message (MessageType enum)
            command_word: CommandWord or list of CommandWords (for RT-to-RT)
            status_word: Optional StatusWord or list of StatusWords
            data_words: Optional list of DataWords
            timestamp: Message timestamp (defaults to current time)
            bus_id: Bus identifier ('A' or 'B')
            gap_time: Inter-message gap time in microseconds
            metadata: Optional metadata dictionary

        Raises:
            MessageStructureException: If message structure is invalid
        """
        self.message_type = message_type
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.bus_id = bus_id
        self.gap_time = gap_time
        self.metadata = metadata or {}

        # Handle command word(s)
        if isinstance(command_word, list):
            self.command_words = command_word
        else:
            self.command_words = [command_word]

        # Handle status word(s)
        if status_word is None:
            self.status_words = []
        elif isinstance(status_word, list):
            self.status_words = status_word
        else:
            self.status_words = [status_word]

        # Handle data words
        self.data_words = data_words or []

        # Validate message structure
        self._validate_structure()

    def _validate_structure(self):
        """
        Validate message structure based on message type.

        Raises:
            MessageStructureException: If structure is invalid
        """
        if self.message_type == MessageType.BC_TO_RT:
            # BC-to-RT: 1 command + N data words
            if len(self.command_words) != 1:
                raise MessageStructureException(
                    f"BC-to-RT requires exactly 1 command word, got {len(self.command_words)}"
                )
            if len(self.status_words) != 0:
                # Note: Some implementations may include status, but standard doesn't require it
                pass

        elif self.message_type == MessageType.RT_TO_BC:
            # RT-to-BC: 1 command + 1 status + N data words
            if len(self.command_words) != 1:
                raise MessageStructureException(
                    f"RT-to-BC requires exactly 1 command word, got {len(self.command_words)}"
                )
            if len(self.status_words) < 1:
                raise MessageStructureException(
                    "RT-to-BC requires at least 1 status word"
                )

        elif self.message_type == MessageType.RT_TO_RT:
            # RT-to-RT: 2 commands + 2 status + N data words
            if len(self.command_words) != 2:
                raise MessageStructureException(
                    f"RT-to-RT requires exactly 2 command words, got {len(self.command_words)}"
                )
            if len(self.status_words) != 2:
                raise MessageStructureException(
                    f"RT-to-RT requires exactly 2 status words, got {len(self.status_words)}"
                )

        elif self.message_type == MessageType.MODE_COMMAND:
            # Mode command: 1 command + 1 status (+ optional data for some modes)
            if len(self.command_words) != 1:
                raise MessageStructureException(
                    f"Mode command requires exactly 1 command word, got {len(self.command_words)}"
                )
            if not self.command_words[0].is_mode_command:
                raise MessageStructureException(
                    "Command word must be a mode command (subaddress 0 or 31)"
                )
            if len(self.status_words) < 1:
                raise MessageStructureException(
                    "Mode command requires at least 1 status word"
                )

        elif self.message_type == MessageType.BROADCAST:
            # Broadcast: 1 command (RT=31) + N data words (no status response)
            if len(self.command_words) != 1:
                raise MessageStructureException(
                    f"Broadcast requires exactly 1 command word, got {len(self.command_words)}"
                )
            if not self.command_words[0].is_broadcast:
                raise MessageStructureException(
                    "Broadcast command must have RT address 31"
                )
            # Broadcast typically has no status word response

    def get_word_count(self) -> int:
        """Get total number of words in message."""
        return len(self.command_words) + len(self.status_words) + len(self.data_words)

    def get_data_word_count(self) -> int:
        """Get number of data words."""
        return len(self.data_words)

    def validate_word_count(self) -> bool:
        """
        Validate that actual data word count matches declared count in command word.

        Returns:
            True if word count is valid

        Raises:
            WordCountException: If word count mismatch
        """
        if not self.command_words:
            return True

        cmd = self.command_words[0]

        # Mode commands have special word count handling
        if cmd.is_mode_command:
            return True

        expected_count = cmd.actual_word_count
        actual_count = len(self.data_words)

        if expected_count != actual_count:
            raise WordCountException(
                f"Word count mismatch: command declares {expected_count}, "
                f"but message has {actual_count} data words"
            )

        return True

    def to_wire_format(self, encoding: str = "binary") -> bytes:
        """
        Encode message to wire format.

        Args:
            encoding: "manchester" or "binary"

        Returns:
            Encoded bytes ready for transmission

        Example:
            >>> msg = Message(MessageType.BC_TO_RT, cmd, data_words=[data1, data2])
            >>> wire_data = msg.to_wire_format(encoding="manchester")
        """
        # Collect all words in transmission order
        words = []

        if self.message_type == MessageType.BC_TO_RT:
            # Order: Command, Data...
            words.extend(self.command_words)
            words.extend(self.data_words)

        elif self.message_type == MessageType.RT_TO_BC:
            # Order: Command, Status, Data...
            words.extend(self.command_words)
            words.extend(self.status_words)
            words.extend(self.data_words)

        elif self.message_type == MessageType.RT_TO_RT:
            # Order: Cmd(rx), Cmd(tx), Status(rx), Data..., Status(tx)
            words.append(self.command_words[0])  # Receive command
            words.append(self.command_words[1])  # Transmit command
            words.append(self.status_words[0])   # Receive status
            words.extend(self.data_words)
            words.append(self.status_words[1])   # Transmit status

        elif self.message_type == MessageType.MODE_COMMAND:
            # Order: Command, Status, (optional data)
            words.extend(self.command_words)
            words.extend(self.status_words)
            words.extend(self.data_words)

        elif self.message_type == MessageType.BROADCAST:
            # Order: Command, Data...
            words.extend(self.command_words)
            words.extend(self.data_words)

        # Encode using selected encoding
        if encoding.lower() == "manchester":
            return bytes(ManchesterEncoder.encode_words(words))
        elif encoding.lower() == "binary":
            return SimpleBinaryEncoder.encode_words(words)
        else:
            raise InvalidValueException(f"Unknown encoding: {encoding}")

    @classmethod
    def from_wire_format(
        cls,
        data: bytes,
        message_type: MessageType,
        encoding: str = "binary",
        timestamp: Optional[float] = None
    ) -> 'Message':
        """
        Decode message from wire format.

        Args:
            data: Encoded bytes
            message_type: Expected message type
            encoding: "manchester" or "binary"
            timestamp: Optional timestamp

        Returns:
            Decoded Message instance

        Example:
            >>> msg = Message.from_wire_format(wire_data, MessageType.BC_TO_RT)
        """
        # Decode words
        if encoding.lower() == "manchester":
            # Determine word count from data length
            word_count = len(data) // TOTAL_WORD_BITS
            words = ManchesterEncoder.decode_words(data, word_count)
        elif encoding.lower() == "binary":
            word_count = len(data) // 3  # 3 bytes per word
            words = SimpleBinaryEncoder.decode_words(data, word_count)
        else:
            raise InvalidValueException(f"Unknown encoding: {encoding}")

        # Parse based on message type
        if message_type == MessageType.BC_TO_RT:
            if len(words) < 1:
                raise MessageStructureException("BC-to-RT needs at least command word")
            return cls(
                message_type=message_type,
                command_word=words[0],
                data_words=words[1:],
                timestamp=timestamp
            )

        elif message_type == MessageType.RT_TO_BC:
            if len(words) < 2:
                raise MessageStructureException("RT-to-BC needs command and status words")
            return cls(
                message_type=message_type,
                command_word=words[0],
                status_word=words[1],
                data_words=words[2:],
                timestamp=timestamp
            )

        else:
            # For other types, basic parsing
            cmd_words = [w for w in words if isinstance(w, CommandWord)]
            status_words = [w for w in words if isinstance(w, StatusWord)]
            data_words = [w for w in words if isinstance(w, DataWord)]

            return cls(
                message_type=message_type,
                command_word=cmd_words,
                status_word=status_words,
                data_words=data_words,
                timestamp=timestamp
            )

    def calculate_message_duration(self) -> float:
        """
        Calculate message duration in microseconds.

        Based on word count and timing constants.

        Returns:
            Duration in microseconds
        """
        total_words = self.get_word_count()

        # Each word takes WORD_TIME microseconds
        word_time = total_words * TimingConstants.WORD_TIME

        # Add response time if applicable (for RT responses)
        if self.message_type in (MessageType.RT_TO_BC, MessageType.MODE_COMMAND):
            word_time += TimingConstants.RESPONSE_TIME_TYPICAL

        # Add inter-message gap if specified
        if self.gap_time is not None:
            word_time += self.gap_time

        return word_time

    def get_response_time(self) -> Optional[float]:
        """
        Get response time for RT responses (if applicable).

        Returns:
            Response time in microseconds, or None if not applicable
        """
        if self.message_type in (MessageType.RT_TO_BC, MessageType.MODE_COMMAND, MessageType.RT_TO_RT):
            # Could be calculated from actual timing or use typical value
            return TimingConstants.RESPONSE_TIME_TYPICAL
        return None

    def add_data_word(self, data_word: DataWord):
        """
        Add a data word to the message.

        Args:
            data_word: DataWord to add
        """
        self.data_words.append(data_word)

        # Update command word count if needed
        if self.command_words and not self.command_words[0].is_mode_command:
            # This would require reconstructing the command word with new count
            # For now, we just append
            pass

    def set_metadata(self, key: str, value: Any):
        """Set metadata value."""
        self.metadata[key] = value

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value."""
        return self.metadata.get(key, default)

    def __repr__(self) -> str:
        return (
            f"Message(type={self.message_type.value}, "
            f"words={self.get_word_count()}, "
            f"data_words={len(self.data_words)})"
        )

    def __str__(self) -> str:
        lines = []
        lines.append(f"Message Type: {self.message_type.value}")
        lines.append(f"Total Words: {self.get_word_count()}")

        if self.command_words:
            lines.append("Command Words:")
            for i, cmd in enumerate(self.command_words):
                lines.append(f"  [{i}] {cmd}")

        if self.status_words:
            lines.append("Status Words:")
            for i, status in enumerate(self.status_words):
                lines.append(f"  [{i}] {status}")

        if self.data_words:
            lines.append(f"Data Words ({len(self.data_words)}):")
            for i, data in enumerate(self.data_words):
                lines.append(f"  [{i}] {data}")

        return "\n".join(lines)


class MessageBuilder:
    """
    Builder pattern for constructing complex messages.

    Provides a fluent interface for building messages step by step.

    Example:
        >>> msg = (MessageBuilder()
        ...        .set_type(MessageType.BC_TO_RT)
        ...        .add_command(cmd)
        ...        .add_data(data1)
        ...        .add_data(data2)
        ...        .build())
    """

    def __init__(self):
        self._message_type = None
        self._command_words = []
        self._status_words = []
        self._data_words = []
        self._timestamp = None
        self._bus_id = 'A'
        self._gap_time = None
        self._metadata = {}

    def set_type(self, message_type: MessageType) -> 'MessageBuilder':
        """Set message type."""
        self._message_type = message_type
        return self

    def add_command(self, command_word: CommandWord) -> 'MessageBuilder':
        """Add a command word."""
        self._command_words.append(command_word)
        return self

    def add_status(self, status_word: StatusWord) -> 'MessageBuilder':
        """Add a status word."""
        self._status_words.append(status_word)
        return self

    def add_data(self, data_word: DataWord) -> 'MessageBuilder':
        """Add a data word."""
        self._data_words.append(data_word)
        return self

    def add_data_list(self, data_words: List[DataWord]) -> 'MessageBuilder':
        """Add multiple data words."""
        self._data_words.extend(data_words)
        return self

    def set_timestamp(self, timestamp: float) -> 'MessageBuilder':
        """Set timestamp."""
        self._timestamp = timestamp
        return self

    def set_bus_id(self, bus_id: str) -> 'MessageBuilder':
        """Set bus ID."""
        self._bus_id = bus_id
        return self

    def set_gap_time(self, gap_time: float) -> 'MessageBuilder':
        """Set inter-message gap time."""
        self._gap_time = gap_time
        return self

    def set_metadata(self, key: str, value: Any) -> 'MessageBuilder':
        """Set metadata value."""
        self._metadata[key] = value
        return self

    def build(self) -> Message:
        """
        Build and return the Message.

        Returns:
            Constructed Message instance

        Raises:
            MessageStructureException: If message structure is invalid
        """
        if self._message_type is None:
            raise MessageStructureException("Message type not set")

        if not self._command_words:
            raise MessageStructureException("At least one command word required")

        return Message(
            message_type=self._message_type,
            command_word=self._command_words if len(self._command_words) > 1 else self._command_words[0],
            status_word=self._status_words if len(self._status_words) > 1 else (self._status_words[0] if self._status_words else None),
            data_words=self._data_words,
            timestamp=self._timestamp,
            bus_id=self._bus_id,
            gap_time=self._gap_time,
            metadata=self._metadata
        )


# Convenience functions for creating common message types

def create_bc_to_rt_message(
    rt_address: int,
    subaddress: int,
    data_words: List[DataWord]
) -> Message:
    """
    Create a BC-to-RT message.

    Args:
        rt_address: Remote terminal address
        subaddress: Subaddress
        data_words: List of data words

    Returns:
        BC-to-RT Message
    """
    from mil1553.core.constants import actual_to_word_count

    word_count = actual_to_word_count(len(data_words))
    cmd = CommandWord(
        rt_address=rt_address,
        transmit_receive=0,  # Receive
        subaddress=subaddress,
        word_count=word_count
    )

    return Message(
        message_type=MessageType.BC_TO_RT,
        command_word=cmd,
        data_words=data_words
    )


def create_rt_to_bc_message(
    rt_address: int,
    subaddress: int,
    data_words: List[DataWord],
    status_word: Optional[StatusWord] = None
) -> Message:
    """
    Create an RT-to-BC message.

    Args:
        rt_address: Remote terminal address
        subaddress: Subaddress
        data_words: List of data words
        status_word: Optional status word (created if not provided)

    Returns:
        RT-to-BC Message
    """
    from mil1553.core.constants import actual_to_word_count

    word_count = actual_to_word_count(len(data_words))
    cmd = CommandWord(
        rt_address=rt_address,
        transmit_receive=1,  # Transmit
        subaddress=subaddress,
        word_count=word_count
    )

    if status_word is None:
        status_word = StatusWord(rt_address=rt_address)

    return Message(
        message_type=MessageType.RT_TO_BC,
        command_word=cmd,
        status_word=status_word,
        data_words=data_words
    )


def create_mode_command_message(
    rt_address: int,
    mode_code: int,
    transmit_receive: int = 1,
    status_word: Optional[StatusWord] = None
) -> Message:
    """
    Create a mode command message.

    Args:
        rt_address: Remote terminal address
        mode_code: Mode code value
        transmit_receive: T/R bit (0 or 1)
        status_word: Optional status word

    Returns:
        Mode command Message
    """
    cmd = CommandWord(
        rt_address=rt_address,
        transmit_receive=transmit_receive,
        subaddress=0,  # Mode command
        word_count=mode_code
    )

    if status_word is None:
        status_word = StatusWord(rt_address=rt_address)

    return Message(
        message_type=MessageType.MODE_COMMAND,
        command_word=cmd,
        status_word=status_word
    )
