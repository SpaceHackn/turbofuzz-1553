"""
Manchester II (Bi-Phase) Encoding/Decoding

This module implements Manchester II encoding and decoding for MIL-STD-1553B.

Manchester II Encoding Rules:
- Logic 0: High-to-Low transition at bit center
- Logic 1: Low-to-High transition at bit center
- Clock rate: 2 MHz (2x the 1 MHz bit rate)
- Each bit period contains exactly one transition at the center

The encoding ensures that there is always a transition at the bit center,
providing self-clocking capability for the receiver.
"""

from typing import List, Tuple, Optional
import struct

from mil1553.core.constants import SyncPattern, TOTAL_WORD_BITS
from mil1553.core.exceptions import ManchesterEncodingException, BitStreamException
from mil1553.core.word import Word, CommandWord, StatusWord, DataWord


class ManchesterEncoder:
    """
    Manchester II (bi-phase) encoder/decoder for MIL-STD-1553B.

    Manchester II encoding ensures self-clocking by guaranteeing a transition
    at every bit center. This is critical for bus synchronization.
    """

    @staticmethod
    def encode_bit(bit: int) -> bytes:
        """
        Encode a single bit using Manchester II encoding.

        Args:
            bit: 0 or 1

        Returns:
            2-byte Manchester encoded representation

        Manchester II:
        - Bit 0: High-Low (0b10)
        - Bit 1: Low-High (0b01)
        """
        if bit == 0:
            return bytes([0b10])  # High-to-Low
        elif bit == 1:
            return bytes([0b01])  # Low-to-High
        else:
            raise ManchesterEncodingException(f"Invalid bit value: {bit}. Must be 0 or 1.")

    @staticmethod
    def decode_bit(encoded: bytes) -> int:
        """
        Decode a single Manchester II encoded bit.

        Args:
            encoded: 2-bit Manchester encoded value

        Returns:
            Decoded bit (0 or 1)

        Raises:
            ManchesterEncodingException: If encoding is invalid
        """
        if len(encoded) < 1:
            raise BitStreamException("Insufficient data for Manchester decoding")

        pattern = encoded[0] & 0b11

        if pattern == 0b10:  # High-to-Low
            return 0
        elif pattern == 0b01:  # Low-to-High
            return 1
        else:
            raise ManchesterEncodingException(
                f"Invalid Manchester encoding: {pattern:02b}. Expected 01 or 10."
            )

    @classmethod
    def encode(cls, data: int, bit_count: int) -> bytearray:
        """
        Encode multiple bits using Manchester II encoding.

        Args:
            data: Data value to encode
            bit_count: Number of bits to encode

        Returns:
            Manchester encoded bytearray

        Example:
            >>> encoder = ManchesterEncoder()
            >>> encoder.encode(0b1010, 4)
            # Returns encoded representation of 1010
        """
        encoded = bytearray()

        for i in range(bit_count - 1, -1, -1):
            bit = (data >> i) & 1

            # Manchester encoding for each bit
            if bit == 0:
                encoded.extend([0b10])  # High-to-Low
            else:
                encoded.extend([0b01])  # Low-to-High

        return encoded

    @classmethod
    def decode(cls, encoded: bytes, bit_count: int) -> int:
        """
        Decode Manchester II encoded data.

        Args:
            encoded: Manchester encoded bytes
            bit_count: Expected number of bits to decode

        Returns:
            Decoded integer value

        Raises:
            ManchesterEncodingException: If encoding is invalid
            BitStreamException: If insufficient data
        """
        if len(encoded) < bit_count:
            raise BitStreamException(
                f"Insufficient data: need {bit_count} bytes, got {len(encoded)}"
            )

        result = 0

        for i in range(bit_count):
            if i >= len(encoded):
                raise BitStreamException(f"Unexpected end of data at bit {i}")

            pattern = encoded[i] & 0b11

            if pattern == 0b10:  # High-to-Low = 0
                bit = 0
            elif pattern == 0b01:  # Low-to-High = 1
                bit = 1
            else:
                raise ManchesterEncodingException(
                    f"Invalid Manchester pattern at position {i}: {pattern:02b}"
                )

            result = (result << 1) | bit

        return result

    @classmethod
    def encode_word(cls, word: Word) -> bytearray:
        """
        Encode a complete MIL-STD-1553B word (20 bits) using Manchester II.

        Args:
            word: Word instance to encode

        Returns:
            Manchester encoded bytearray (20 bytes for 20 bits)

        Example:
            >>> cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
            >>> encoded = ManchesterEncoder.encode_word(cmd)
        """
        return cls.encode(word.raw_value, TOTAL_WORD_BITS)

    @classmethod
    def decode_word(cls, encoded: bytes, word_type: Optional[type] = None) -> Word:
        """
        Decode a Manchester II encoded word.

        Args:
            encoded: Manchester encoded bytes (at least 20 bytes)
            word_type: Optional expected word type (CommandWord, StatusWord, DataWord)

        Returns:
            Decoded Word instance

        Raises:
            ManchesterEncodingException: If decoding fails
        """
        if len(encoded) < TOTAL_WORD_BITS:
            raise BitStreamException(
                f"Insufficient data for word: need {TOTAL_WORD_BITS} bytes, got {len(encoded)}"
            )

        # Decode 20 bits
        raw_value = cls.decode(encoded, TOTAL_WORD_BITS)

        # Extract components
        sync = (raw_value >> 17) & 0x7
        data = (raw_value >> 1) & 0xFFFF
        parity = raw_value & 0x1

        # Determine word type from sync if not provided
        if word_type is None:
            if sync == SyncPattern.COMMAND_STATUS:
                # Could be Command or Status - we'll default to Command
                # In real decoding, context would determine this
                word_type = CommandWord
            elif sync == SyncPattern.DATA:
                word_type = DataWord
            else:
                raise ManchesterEncodingException(f"Invalid sync pattern: {sync:#05b}")

        # Create appropriate word type
        return word_type._from_parts(sync, data, parity, None)

    @classmethod
    def detect_sync(cls, signal: bytes, start_position: int = 0) -> Tuple[int, int]:
        """
        Detect sync pattern in a Manchester encoded signal.

        Searches for valid sync patterns (0b100 for command/status or 0b000 for data).

        Args:
            signal: Manchester encoded signal
            start_position: Position to start searching from

        Returns:
            Tuple of (position, sync_value) where sync pattern was found

        Raises:
            ManchesterEncodingException: If no sync pattern found
        """
        if len(signal) < 3:
            raise BitStreamException("Signal too short to contain sync pattern")

        # Search for sync pattern (3 bits)
        for pos in range(start_position, len(signal) - 2):
            try:
                # Try to decode 3 bits
                sync_candidate = cls.decode(signal[pos:pos+3], 3)

                # Check if it's a valid sync pattern
                if sync_candidate in (SyncPattern.COMMAND_STATUS, SyncPattern.DATA):
                    return (pos, sync_candidate)

            except ManchesterEncodingException:
                # Invalid Manchester encoding at this position, continue searching
                continue

        raise ManchesterEncodingException("No valid sync pattern found in signal")

    @classmethod
    def validate_encoding(cls, signal: bytes, bit_count: int) -> bool:
        """
        Validate that a signal contains valid Manchester II encoding.

        Args:
            signal: Signal to validate
            bit_count: Expected number of bits

        Returns:
            True if encoding is valid

        Raises:
            ManchesterEncodingException: If encoding is invalid
        """
        try:
            cls.decode(signal, bit_count)
            return True
        except (ManchesterEncodingException, BitStreamException):
            return False

    @classmethod
    def encode_words(cls, words: List[Word]) -> bytearray:
        """
        Encode multiple words into a continuous Manchester II stream.

        Args:
            words: List of Word instances

        Returns:
            Continuous Manchester encoded bytearray

        Example:
            >>> cmd = CommandWord(...)
            >>> data1 = DataWord(payload=0x1234)
            >>> data2 = DataWord(payload=0x5678)
            >>> encoded = ManchesterEncoder.encode_words([cmd, data1, data2])
        """
        encoded = bytearray()

        for word in words:
            encoded.extend(cls.encode_word(word))

        return encoded

    @classmethod
    def decode_words(cls, encoded: bytes, word_count: int) -> List[Word]:
        """
        Decode multiple words from a continuous Manchester II stream.

        Args:
            encoded: Manchester encoded bytes
            word_count: Number of words to decode

        Returns:
            List of decoded Word instances

        Raises:
            ManchesterEncodingException: If decoding fails
            BitStreamException: If insufficient data
        """
        if len(encoded) < word_count * TOTAL_WORD_BITS:
            raise BitStreamException(
                f"Insufficient data: need {word_count * TOTAL_WORD_BITS} bytes for {word_count} words"
            )

        words = []
        offset = 0

        for i in range(word_count):
            word_data = encoded[offset:offset + TOTAL_WORD_BITS]
            word = cls.decode_word(word_data)
            words.append(word)
            offset += TOTAL_WORD_BITS

        return words


class SimpleBinaryEncoder:
    """
    Simple binary encoder (non-Manchester) for testing and debugging.

    This encoder simply packs bits into bytes without Manchester encoding.
    Useful for testing and when Manchester encoding is not required.
    """

    @staticmethod
    def encode_word(word: Word) -> bytes:
        """
        Encode word as raw binary (3 bytes for 20 bits).

        Args:
            word: Word to encode

        Returns:
            3-byte binary representation
        """
        return word.to_bytes()

    @staticmethod
    def decode_word(data: bytes) -> Word:
        """
        Decode word from raw binary.

        Args:
            data: 3-byte binary data

        Returns:
            Decoded Word instance
        """
        if len(data) < 3:
            raise BitStreamException(f"Need 3 bytes for word, got {len(data)}")

        # Reconstruct 20-bit value from 3 bytes
        raw_value = int.from_bytes(data[:3], byteorder='big') >> 4  # Shift right 4 to get 20 bits

        # Extract components
        sync = (raw_value >> 17) & 0x7
        data_field = (raw_value >> 1) & 0xFFFF
        parity = raw_value & 0x1

        # Determine word type from sync
        if sync == SyncPattern.COMMAND_STATUS:
            return CommandWord._from_parts(sync, data_field, parity, None)
        elif sync == SyncPattern.DATA:
            return DataWord._from_parts(sync, data_field, parity, None)
        else:
            raise ManchesterEncodingException(f"Invalid sync pattern: {sync:#05b}")

    @staticmethod
    def encode_words(words: List[Word]) -> bytes:
        """
        Encode multiple words as raw binary.

        Args:
            words: List of words

        Returns:
            Binary data
        """
        result = bytearray()
        for word in words:
            result.extend(SimpleBinaryEncoder.encode_word(word))
        return bytes(result)

    @staticmethod
    def decode_words(data: bytes, word_count: int) -> List[Word]:
        """
        Decode multiple words from raw binary.

        Args:
            data: Binary data
            word_count: Number of words to decode

        Returns:
            List of decoded words
        """
        words = []
        offset = 0

        for i in range(word_count):
            word = SimpleBinaryEncoder.decode_word(data[offset:offset+3])
            words.append(word)
            offset += 3

        return words


def get_encoder(encoding_type: str = "manchester"):
    """
    Factory function to get appropriate encoder.

    Args:
        encoding_type: "manchester" or "binary"

    Returns:
        Encoder class

    Example:
        >>> encoder = get_encoder("manchester")
        >>> encoded = encoder.encode_word(word)
    """
    if encoding_type.lower() == "manchester":
        return ManchesterEncoder
    elif encoding_type.lower() == "binary":
        return SimpleBinaryEncoder
    else:
        raise ValueError(f"Unknown encoding type: {encoding_type}")
