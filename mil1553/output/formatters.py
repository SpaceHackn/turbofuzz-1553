"""
Output Formatters for MIL-STD-1553B Messages and Words

This module provides various output formats for displaying and analyzing
MIL-STD-1553B messages and words. Useful for debugging, security testing,
and documentation.
"""

from typing import List, Optional, Union
from abc import ABC, abstractmethod

from mil1553.core.word import Word, CommandWord, StatusWord, DataWord
from mil1553.core.message import Message
from mil1553.core.constants import MessageType, SyncPattern


class OutputFormatter(ABC):
    """
    Abstract base class for output formatters.

    All formatters implement methods to format words and messages
    into human-readable representations.
    """

    @abstractmethod
    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Format a single word."""
        pass

    @abstractmethod
    def format_message(self, message: Message) -> str:
        """Format a complete message."""
        pass

    def format_batch(self, messages: List[Message]) -> str:
        """Format multiple messages."""
        lines = []
        for i, msg in enumerate(messages):
            lines.append(f"\n{'='*70}")
            lines.append(f"Message {i}")
            lines.append('='*70)
            lines.append(self.format_message(msg))
        return '\n'.join(lines)


class BinaryFormatter(OutputFormatter):
    """
    Raw binary output formatter.

    Outputs raw bytes suitable for transmission or storage.
    """

    def __init__(self, encoding: str = "binary"):
        """
        Initialize binary formatter.

        Args:
            encoding: "binary" or "manchester"
        """
        self.encoding = encoding

    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Return word as raw bytes (hex representation)."""
        return word.to_bytes().hex()

    def format_message(self, message: Message) -> str:
        """Return message as raw bytes (hex representation)."""
        wire_data = message.to_wire_format(encoding=self.encoding)
        return wire_data.hex()


class HexFormatter(OutputFormatter):
    """
    Hex dump formatter.

    Provides traditional hex dump output with configurable width.
    """

    def __init__(self, bytes_per_line: int = 16, show_ascii: bool = True):
        """
        Initialize hex formatter.

        Args:
            bytes_per_line: Number of bytes per line
            show_ascii: Show ASCII representation
        """
        self.bytes_per_line = bytes_per_line
        self.show_ascii = show_ascii

    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Format word as hex dump."""
        data = word.to_bytes()
        hex_str = ' '.join(f'{b:02X}' for b in data)

        if index is not None:
            return f"{index:04d}: {hex_str}"
        return hex_str

    def format_message(self, message: Message) -> str:
        """Format message as hex dump."""
        wire_data = message.to_wire_format(encoding="binary")
        lines = []

        for i in range(0, len(wire_data), self.bytes_per_line):
            chunk = wire_data[i:i + self.bytes_per_line]

            # Address
            line = f"{i:04X}: "

            # Hex bytes
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            line += f"{hex_part:<{self.bytes_per_line * 3}}"

            # ASCII representation
            if self.show_ascii:
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                line += f"  |{ascii_part}|"

            lines.append(line)

        return '\n'.join(lines)


class AnnotatedHexFormatter(OutputFormatter):
    """
    Annotated hex dump formatter.

    Provides hex output with inline field annotations showing the
    meaning of each word and its fields.
    """

    def __init__(self, show_binary: bool = False, show_parity: bool = True):
        """
        Initialize annotated formatter.

        Args:
            show_binary: Show binary representation
            show_parity: Show parity information
        """
        self.show_binary = show_binary
        self.show_parity = show_parity

    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Format word with field annotations."""
        lines = []

        # Word index
        prefix = f"[{index}] " if index is not None else ""

        # Hex representation
        hex_str = word.to_hex()
        lines.append(f"{prefix}0x{hex_str}")

        # Binary representation
        if self.show_binary:
            binary = word.to_binary_string('_')
            lines.append(f"    Binary: 0b{binary}")

        # Type-specific annotations
        if isinstance(word, CommandWord):
            lines.extend(self._annotate_command_word(word))
        elif isinstance(word, StatusWord):
            lines.extend(self._annotate_status_word(word))
        elif isinstance(word, DataWord):
            lines.extend(self._annotate_data_word(word))

        # Parity information
        if self.show_parity:
            parity_status = "✓" if word.is_valid_parity() else "✗"
            lines.append(f"    Parity: {word.parity} {parity_status}")

        return '\n'.join(lines)

    def _annotate_command_word(self, word: CommandWord) -> List[str]:
        """Annotate command word fields."""
        annotations = [
            f"    Type: Command Word",
            f"    RT Address: {word.rt_address}" + (" (BROADCAST)" if word.is_broadcast else ""),
            f"    T/R: {word.transmit_receive} ({'Transmit' if word.transmit_receive else 'Receive'})",
            f"    Subaddress: {word.subaddress}" + (" (MODE COMMAND)" if word.is_mode_command else ""),
            f"    Word Count: {word.word_count_mode} ({word.actual_word_count} words)" if not word.is_mode_command else f"    Mode Code: {word.mode_code.name if word.mode_code else word.word_count_mode}"
        ]
        return annotations

    def _annotate_status_word(self, word: StatusWord) -> List[str]:
        """Annotate status word fields."""
        annotations = [
            f"    Type: Status Word",
            f"    RT Address: {word.rt_address}",
        ]

        # Show active flags
        active_flags = word.get_active_flags()
        if active_flags:
            annotations.append(f"    Flags: {', '.join(active_flags)}")
        else:
            annotations.append(f"    Flags: (none)")

        return annotations

    def _annotate_data_word(self, word: DataWord) -> List[str]:
        """Annotate data word fields."""
        annotations = [
            f"    Type: Data Word",
            f"    Payload: 0x{word.payload:04X} ({word.to_unsigned_int()} unsigned, {word.to_signed_int()} signed)"
        ]
        return annotations

    def format_message(self, message: Message) -> str:
        """Format message with annotations."""
        lines = []

        # Message header
        lines.append(f"Message Type: {message.message_type.value.upper()}")
        lines.append(f"Total Words: {message.get_word_count()}")
        lines.append(f"Duration: {message.calculate_message_duration():.2f} μs")
        lines.append("")

        word_index = 0

        # Command words
        if message.command_words:
            lines.append("Command Words:")
            for cmd in message.command_words:
                lines.append(self.format_word(cmd, word_index))
                lines.append("")
                word_index += 1

        # Status words
        if message.status_words:
            lines.append("Status Words:")
            for status in message.status_words:
                lines.append(self.format_word(status, word_index))
                lines.append("")
                word_index += 1

        # Data words
        if message.data_words:
            lines.append(f"Data Words ({len(message.data_words)}):")
            for data in message.data_words:
                lines.append(self.format_word(data, word_index))
                lines.append("")
                word_index += 1

        return '\n'.join(lines)


class CompactHexFormatter(OutputFormatter):
    """
    Compact hex formatter for one-line output.

    Useful for logging and quick inspection.
    """

    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Format word as compact hex."""
        prefix = f"[{index}] " if index is not None else ""

        if isinstance(word, CommandWord):
            return f"{prefix}CMD: RT={word.rt_address} T/R={word.transmit_receive} SA={word.subaddress} WC={word.word_count_mode} | 0x{word.to_hex()}"
        elif isinstance(word, StatusWord):
            flags = ','.join(word.get_active_flags()) if word.get_active_flags() else 'OK'
            return f"{prefix}STS: RT={word.rt_address} [{flags}] | 0x{word.to_hex()}"
        elif isinstance(word, DataWord):
            return f"{prefix}DAT: 0x{word.payload:04X} | 0x{word.to_hex()}"
        else:
            return f"{prefix}0x{word.to_hex()}"

    def format_message(self, message: Message) -> str:
        """Format message as compact hex."""
        parts = [f"{message.message_type.value.upper()}"]

        # Add word representations
        for cmd in message.command_words:
            parts.append(self.format_word(cmd))
        for status in message.status_words:
            parts.append(self.format_word(status))
        for i, data in enumerate(message.data_words):
            if i < 3:  # Show first 3 data words
                parts.append(self.format_word(data))
            elif i == 3:
                parts.append(f"... +{len(message.data_words)-3} more")
                break

        return ' | '.join(parts)


class VisualFormatter(OutputFormatter):
    """
    Visual ASCII art formatter.

    Creates visual representation of packet structure.
    """

    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Format word as visual ASCII art."""
        lines = []

        # Header
        lines.append("┌" + "─" * 68 + "┐")

        # Word type
        if isinstance(word, CommandWord):
            word_type = "COMMAND WORD"
        elif isinstance(word, StatusWord):
            word_type = "STATUS WORD"
        elif isinstance(word, DataWord):
            word_type = "DATA WORD"
        else:
            word_type = "WORD"

        lines.append(f"│ {word_type:<66} │")
        lines.append("├" + "─" * 68 + "┤")

        # Binary representation with field markers
        binary = word.to_binary_string()

        # Sync (3 bits), Data (16 bits), Parity (1 bit)
        sync_bits = binary[0:3]
        data_bits = binary[3:19]
        parity_bit = binary[19:20]

        lines.append(f"│ Sync │{'Data (16 bits)':<50}│P│")
        lines.append(f"│ {sync_bits}  │ {data_bits[:8]} {data_bits[8:16]:<42}│{parity_bit}│")
        lines.append("├" + "─" * 68 + "┤")

        # Field details
        if isinstance(word, CommandWord):
            lines.append(f"│ RT Addr: {word.rt_address:<2} │ T/R: {word.transmit_receive} │ Subaddr: {word.subaddress:<2} │ Word Count: {word.word_count_mode:<14} │")
        elif isinstance(word, StatusWord):
            flags_str = ', '.join(word.get_active_flags()[:3]) if word.get_active_flags() else 'None'
            lines.append(f"│ RT Addr: {word.rt_address:<2} │ Flags: {flags_str:<49} │")
        elif isinstance(word, DataWord):
            lines.append(f"│ Payload: 0x{word.payload:04X} ({word.to_unsigned_int():<5} unsigned, {word.to_signed_int():<6} signed)        │")

        # Footer
        lines.append("└" + "─" * 68 + "┘")

        return '\n'.join(lines)

    def format_message(self, message: Message) -> str:
        """Format message as visual ASCII art."""
        lines = []

        # Message header
        lines.append("╔" + "═" * 68 + "╗")
        lines.append(f"║ MESSAGE: {message.message_type.value.upper():<56} ║")
        lines.append(f"║ Words: {message.get_word_count():<3} │ Duration: {message.calculate_message_duration():.2f} μs{'':<39} ║")
        lines.append("╚" + "═" * 68 + "╝")
        lines.append("")

        # Words
        all_words = message.command_words + message.status_words + message.data_words
        for i, word in enumerate(all_words):
            lines.append(self.format_word(word, i))
            if i < len(all_words) - 1:
                lines.append("     ↓")

        return '\n'.join(lines)


class JSONFormatter(OutputFormatter):
    """
    JSON formatter for programmatic processing.
    """

    def format_word(self, word: Word, index: Optional[int] = None) -> str:
        """Format word as JSON."""
        import json

        data = {
            'index': index,
            'type': word.__class__.__name__,
            'hex': word.to_hex(),
            'raw_value': word.raw_value,
            'sync': word.sync,
            'parity': word.parity,
            'parity_valid': word.is_valid_parity()
        }

        if isinstance(word, CommandWord):
            data.update({
                'rt_address': word.rt_address,
                'transmit_receive': word.transmit_receive,
                'subaddress': word.subaddress,
                'word_count': word.word_count_mode,
                'is_broadcast': word.is_broadcast,
                'is_mode_command': word.is_mode_command
            })
        elif isinstance(word, StatusWord):
            data.update({
                'rt_address': word.rt_address,
                'flags': word.get_active_flags()
            })
        elif isinstance(word, DataWord):
            data.update({
                'payload': word.payload,
                'unsigned': word.to_unsigned_int(),
                'signed': word.to_signed_int()
            })

        return json.dumps(data, indent=2)

    def format_message(self, message: Message) -> str:
        """Format message as JSON."""
        import json

        data = {
            'message_type': message.message_type.value,
            'total_words': message.get_word_count(),
            'duration_us': message.calculate_message_duration(),
            'timestamp': message.timestamp,
            'bus_id': message.bus_id,
            'command_words': [self._word_to_dict(w) for w in message.command_words],
            'status_words': [self._word_to_dict(w) for w in message.status_words],
            'data_words': [self._word_to_dict(w) for w in message.data_words]
        }

        return json.dumps(data, indent=2)

    def _word_to_dict(self, word: Word) -> dict:
        """Convert word to dictionary."""
        base = {
            'type': word.__class__.__name__,
            'hex': word.to_hex(),
            'parity_valid': word.is_valid_parity()
        }

        if isinstance(word, CommandWord):
            base.update({
                'rt_address': word.rt_address,
                'transmit_receive': word.transmit_receive,
                'subaddress': word.subaddress,
                'word_count': word.word_count_mode
            })
        elif isinstance(word, StatusWord):
            base.update({
                'rt_address': word.rt_address,
                'flags': word.get_active_flags()
            })
        elif isinstance(word, DataWord):
            base.update({
                'payload': word.payload
            })

        return base


# Formatter factory
def get_formatter(format_type: str, **kwargs) -> OutputFormatter:
    """
    Factory function to get appropriate formatter.

    Args:
        format_type: "binary", "hex", "annotated", "compact", "visual", "json"
        **kwargs: Additional formatter-specific arguments

    Returns:
        OutputFormatter instance

    Example:
        >>> formatter = get_formatter("annotated", show_binary=True)
        >>> print(formatter.format_message(message))
    """
    formatters = {
        'binary': BinaryFormatter,
        'hex': HexFormatter,
        'annotated': AnnotatedHexFormatter,
        'compact': CompactHexFormatter,
        'visual': VisualFormatter,
        'json': JSONFormatter
    }

    formatter_class = formatters.get(format_type.lower())
    if formatter_class is None:
        raise ValueError(f"Unknown format type: {format_type}. Choose from: {list(formatters.keys())}")

    return formatter_class(**kwargs)
