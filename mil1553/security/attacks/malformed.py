"""
Malformed Packet Generation for MIL-STD-1553B Security Testing

This module provides functions to generate protocol-violating packets
for testing implementation robustness and security.
"""

from typing import List, Optional
import random

from mil1553.core.word import Word, CommandWord, StatusWord, DataWord
from mil1553.core.message import Message, MessageType
from mil1553.core.constants import (
    SyncPattern, MAX_RT_ADDRESS, MAX_SUBADDRESS,
    BROADCAST_ADDRESS
)
from mil1553.utils.bitops import flip_bit, set_bits


class MalformedPacketGenerator:
    """
    Generates protocol-violating MIL-STD-1553B packets.

    Useful for testing implementation resilience to malformed inputs.
    """

    @staticmethod
    def generate_invalid_sync(word: Word, sync_value: Optional[int] = None) -> Word:
        """
        Generate word with invalid sync pattern.

        Args:
            word: Original word
            sync_value: Specific sync value to use (random if None)

        Returns:
            Word with invalid sync

        Standard Violation: §4.3.5.2.1
        """
        if sync_value is None:
            # Generate invalid sync (not 0b000 or 0b100)
            invalid_syncs = [0b001, 0b010, 0b011, 0b101, 0b110, 0b111]
            sync_value = random.choice(invalid_syncs)

        # Reconstruct word with invalid sync
        return word.__class__._from_parts(sync_value, word.data, word.parity, word.timestamp)

    @staticmethod
    def generate_parity_error(word: Word) -> Word:
        """
        Generate word with incorrect parity.

        Args:
            word: Original word

        Returns:
            Word with flipped parity

        Standard Violation: §4.3.5.2.1.2
        """
        return word.corrupt_parity()

    @staticmethod
    def generate_illegal_address(address: int = 255) -> CommandWord:
        """
        Generate command with out-of-range RT address.

        Args:
            address: Illegal address value (> 31)

        Returns:
            CommandWord with illegal address

        Standard Violation: §4.3.5.2.2.1
        """
        # Create command, but force illegal address
        # (This bypasses normal validation)
        cmd = CommandWord.__new__(CommandWord)
        cmd.rt_address = address  # Illegal value
        cmd.transmit_receive = 0
        cmd.subaddress = 10
        cmd.word_count_mode = 3

        # Build data field with illegal address
        cmd.data = (
            (address << 11) |
            (0 << 10) |
            (10 << 5) |
            3
        )
        cmd.sync = SyncPattern.COMMAND_STATUS
        cmd.parity = 0
        cmd.timestamp = None
        cmd._update_raw_value()

        return cmd

    @staticmethod
    def generate_word_count_mismatch(
        message: Message,
        declared_count: Optional[int] = None
    ) -> Message:
        """
        Generate message with word count mismatch.

        Declared count in command word doesn't match actual data words.

        Args:
            message: Original message
            declared_count: Override declared count (random if None)

        Returns:
            Message with word count mismatch

        Standard Violation: §4.3.5.2.2.4
        """
        import copy
        malformed = copy.deepcopy(message)

        if malformed.command_words:
            actual_count = len(malformed.data_words)

            if declared_count is None:
                # Pick a different count
                declared_count = (actual_count + random.randint(1, 10)) % 32

            malformed.command_words[0].word_count_mode = declared_count

        return malformed

    @staticmethod
    def generate_illegal_mode_command(rt_address: int = 5) -> Message:
        """
        Generate message with undefined/reserved mode code.

        Args:
            rt_address: RT address

        Returns:
            Message with illegal mode code

        Standard Violation: §4.3.4.3
        """
        # Use reserved mode code
        reserved_mode_code = random.randint(20, 31)  # Reserved range

        cmd = CommandWord(
            rt_address=rt_address,
            transmit_receive=1,
            subaddress=0,  # Mode command indicator
            word_count=reserved_mode_code  # Illegal mode code
        )

        status = StatusWord(rt_address=rt_address)

        return Message(
            message_type=MessageType.MODE_COMMAND,
            command_word=cmd,
            status_word=status
        )

    @staticmethod
    def generate_malformed_status(rt_address: int = 5) -> StatusWord:
        """
        Generate status word with invalid bit combinations.

        Args:
            rt_address: RT address

        Returns:
            StatusWord with invalid flags

        Standard Violation: §4.3.5.2.3
        """
        # Create status with conflicting flags
        status = StatusWord(
            rt_address=rt_address,
            message_error=True,  # Error indicated
            busy=False,          # But not busy?
            subsystem_flag=True,
            terminal_flag=True,
            reserved=0b111       # Reserved bits set (should be 0)
        )

        return status

    @staticmethod
    def generate_broadcast_with_response(
        rt_address: int = 31,
        subaddress: int = 10
    ) -> Message:
        """
        Generate broadcast message with (illegal) status response.

        Broadcast messages should not have status responses.

        Args:
            rt_address: Should be 31 (broadcast)
            subaddress: Subaddress

        Returns:
            Illegal broadcast with status

        Standard Violation: §4.3.4.4
        """
        cmd = CommandWord(
            rt_address=BROADCAST_ADDRESS,
            transmit_receive=0,
            subaddress=subaddress,
            word_count=2
        )

        # Broadcast shouldn't have status, but add one anyway
        status = StatusWord(rt_address=5)  # Some RT responds

        data = [DataWord(payload=0x1111), DataWord(payload=0x2222)]

        return Message(
            message_type=MessageType.BROADCAST,
            command_word=cmd,
            status_word=status,  # Illegal for broadcast!
            data_words=data
        )

    @staticmethod
    def generate_wrong_sync_for_type(word: Word) -> Word:
        """
        Generate word with wrong sync for its type.

        Command/Status with DATA sync or Data with COMMAND_STATUS sync.

        Args:
            word: Original word

        Returns:
            Word with wrong sync type

        Standard Violation: §4.3.5.2.1
        """
        if isinstance(word, (CommandWord, StatusWord)):
            # Should have COMMAND_STATUS (0b100), give DATA (0b000)
            wrong_sync = SyncPattern.DATA
        else:
            # Should have DATA (0b000), give COMMAND_STATUS (0b100)
            wrong_sync = SyncPattern.COMMAND_STATUS

        return word.__class__._from_parts(wrong_sync, word.data, word.parity, word.timestamp)

    @staticmethod
    def generate_all_zeros_word() -> Word:
        """
        Generate word with all zeros (invalid).

        Returns:
            All-zeros word
        """
        return DataWord._from_parts(0, 0, 0, None)

    @staticmethod
    def generate_all_ones_word() -> Word:
        """
        Generate word with all ones.

        Returns:
            All-ones word
        """
        return DataWord._from_parts(0b111, 0xFFFF, 1, None)

    @staticmethod
    def generate_alternating_bits_word() -> Word:
        """
        Generate word with alternating bit pattern.

        Returns:
            Alternating-bits word
        """
        # 0xAAAA = 1010101010101010
        return DataWord(payload=0xAAAA)

    @staticmethod
    def generate_address_mismatch(message: Message) -> Message:
        """
        Generate message with RT address mismatch.

        Command and status words have different RT addresses.

        Args:
            message: Original message

        Returns:
            Message with address mismatch

        Standard Violation: Protocol consistency
        """
        import copy
        malformed = copy.deepcopy(message)

        if malformed.command_words and malformed.status_words:
            cmd_addr = malformed.command_words[0].rt_address
            # Set status to different address
            malformed.status_words[0].rt_address = (cmd_addr + 1) % 32

        return malformed

    @staticmethod
    def generate_excessive_data_words(message: Message, extra_count: int = 10) -> Message:
        """
        Generate message with more data words than declared.

        Args:
            message: Original message
            extra_count: Number of extra words to add

        Returns:
            Message with excessive data

        Standard Violation: §4.3.5.2.2.4
        """
        import copy
        malformed = copy.deepcopy(message)

        # Add extra data words
        for i in range(extra_count):
            malformed.data_words.append(DataWord(payload=0xEEEE + i))

        return malformed

    @staticmethod
    def generate_malformed_suite(template: Message) -> List[Message]:
        """
        Generate a complete suite of malformed variants.

        Args:
            template: Template message

        Returns:
            List of malformed messages

        Example:
            >>> template = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1234)])
            >>> suite = MalformedPacketGenerator.generate_malformed_suite(template)
            >>> # Returns ~10 different malformations
        """
        gen = MalformedPacketGenerator

        suite = []

        # Word count mismatches
        for declared in [0, 1, 5, 10, 31]:
            suite.append(gen.generate_word_count_mismatch(template, declared))

        # Address mismatch (if applicable)
        if template.status_words:
            suite.append(gen.generate_address_mismatch(template))

        # Excessive data
        suite.append(gen.generate_excessive_data_words(template, 5))
        suite.append(gen.generate_excessive_data_words(template, 20))

        # Parity errors on different words
        import copy
        for word_list in [template.command_words, template.status_words, template.data_words]:
            if word_list:
                msg = copy.deepcopy(template)
                word_list[0] = gen.generate_parity_error(word_list[0])
                suite.append(msg)

        # Invalid sync patterns
        for word_list in [template.command_words, template.data_words]:
            if word_list:
                msg = copy.deepcopy(template)
                word_list[0] = gen.generate_invalid_sync(word_list[0])
                suite.append(msg)

        return suite


# Convenience functions

def corrupt_random_bits(word: Word, bit_count: int = 1) -> Word:
    """
    Corrupt random bits in a word.

    Args:
        word: Word to corrupt
        bit_count: Number of bits to flip

    Returns:
        Corrupted word
    """
    raw = word.raw_value

    for _ in range(bit_count):
        bit_pos = random.randint(0, 19)
        raw = flip_bit(raw, bit_pos)

    sync = (raw >> 17) & 0x7
    data = (raw >> 1) & 0xFFFF
    parity = raw & 0x1

    return word.__class__._from_parts(sync, data, parity, word.timestamp)


def create_malformed_message(
    violation_type: str,
    **kwargs
) -> Message:
    """
    Factory function to create specific malformed messages.

    Args:
        violation_type: Type of violation
        **kwargs: Parameters for specific violation

    Returns:
        Malformed message

    Example:
        >>> msg = create_malformed_message('word_count_mismatch', declared_count=10)
        >>> msg = create_malformed_message('illegal_mode_code', rt_address=5)
    """
    gen = MalformedPacketGenerator

    if violation_type == 'illegal_mode_code':
        return gen.generate_illegal_mode_command(kwargs.get('rt_address', 5))

    elif violation_type == 'broadcast_with_response':
        return gen.generate_broadcast_with_response(
            kwargs.get('rt_address', 31),
            kwargs.get('subaddress', 10)
        )

    else:
        raise ValueError(f"Unknown violation type: {violation_type}")
