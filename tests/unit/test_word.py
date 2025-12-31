"""
Unit tests for MIL-STD-1553B Word classes
"""

import pytest
from mil1553.core import CommandWord, StatusWord, DataWord, SyncPattern, MessageType
from mil1553.core.exceptions import ParityException, AddressException, SubaddressException


class TestCommandWord:
    """Tests for CommandWord class"""

    def test_create_command_word(self):
        """Test creating a basic command word"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        assert cmd.rt_address == 5
        assert cmd.transmit_receive == 0
        assert cmd.subaddress == 10
        assert cmd.word_count_mode == 3
        assert cmd.sync == SyncPattern.COMMAND_STATUS
        assert cmd.is_valid_parity()

    def test_broadcast_command(self):
        """Test broadcast command (RT address 31)"""
        cmd = CommandWord(rt_address=31, transmit_receive=0, subaddress=5, word_count=10)
        assert cmd.is_broadcast
        assert cmd.get_message_type() == MessageType.BROADCAST

    def test_mode_command(self):
        """Test mode command (subaddress 0)"""
        cmd = CommandWord(rt_address=5, transmit_receive=1, subaddress=0, word_count=2)
        assert cmd.is_mode_command
        assert cmd.get_message_type() == MessageType.MODE_COMMAND

    def test_bc_to_rt_message_type(self):
        """Test BC-to-RT message type"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        assert cmd.get_message_type() == MessageType.BC_TO_RT

    def test_rt_to_bc_message_type(self):
        """Test RT-to-BC message type"""
        cmd = CommandWord(rt_address=5, transmit_receive=1, subaddress=10, word_count=3)
        assert cmd.get_message_type() == MessageType.RT_TO_BC

    def test_actual_word_count(self):
        """Test word count conversion (0 = 32 words)"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=0)
        assert cmd.actual_word_count == 32

        cmd2 = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=10)
        assert cmd2.actual_word_count == 10

    def test_invalid_address(self):
        """Test invalid RT address raises exception"""
        with pytest.raises(AddressException):
            CommandWord(rt_address=32, transmit_receive=0, subaddress=10, word_count=3)

    def test_invalid_subaddress(self):
        """Test invalid subaddress raises exception"""
        with pytest.raises(SubaddressException):
            CommandWord(rt_address=5, transmit_receive=0, subaddress=32, word_count=3)

    def test_parity_corruption(self):
        """Test parity corruption for security testing"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        corrupted = cmd.corrupt_parity()

        assert cmd.is_valid_parity()
        assert not corrupted.is_valid_parity()
        assert cmd.parity != corrupted.parity

    def test_sync_corruption(self):
        """Test sync corruption for security testing"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        corrupted = cmd.corrupt_sync()

        assert cmd.sync == SyncPattern.COMMAND_STATUS
        assert corrupted.sync == SyncPattern.DATA

    def test_to_hex(self):
        """Test hex representation"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        hex_str = cmd.to_hex()
        assert len(hex_str) == 5  # 20 bits = 5 hex digits


class TestStatusWord:
    """Tests for StatusWord class"""

    def test_create_status_word(self):
        """Test creating a basic status word"""
        status = StatusWord(rt_address=5)
        assert status.rt_address == 5
        assert status.sync == SyncPattern.COMMAND_STATUS
        assert status.is_valid_parity()

    def test_status_flags(self):
        """Test status word flags"""
        status = StatusWord(
            rt_address=5,
            message_error=True,
            busy=True,
            service_request=True
        )

        assert status.message_error
        assert status.busy
        assert status.service_request
        assert not status.subsystem_flag

        active_flags = status.get_active_flags()
        assert "MESSAGE_ERROR" in active_flags
        assert "BUSY" in active_flags
        assert "SERVICE_REQUEST" in active_flags

    def test_clear_all_flags(self):
        """Test clearing all flags"""
        status = StatusWord(
            rt_address=5,
            message_error=True,
            busy=True,
            service_request=True
        )

        status.clear_all_flags()
        assert not status.message_error
        assert not status.busy
        assert not status.service_request
        assert len(status.get_active_flags()) == 0


class TestDataWord:
    """Tests for DataWord class"""

    def test_create_data_word(self):
        """Test creating a data word"""
        data = DataWord(payload=0x1234)
        assert data.payload == 0x1234
        assert data.sync == SyncPattern.DATA
        assert data.is_valid_parity()

    def test_signed_interpretation(self):
        """Test signed integer interpretation"""
        # Positive number
        data1 = DataWord(payload=0x1234)
        assert data1.to_signed_int() == 0x1234

        # Negative number (MSB set)
        data2 = DataWord(payload=0xFFFF)
        assert data2.to_signed_int() == -1

        data3 = DataWord(payload=0x8000)
        assert data3.to_signed_int() == -32768

    def test_unsigned_interpretation(self):
        """Test unsigned integer interpretation"""
        data = DataWord(payload=0xFFFF)
        assert data.to_unsigned_int() == 65535

    def test_from_bytes(self):
        """Test creating data word from bytes"""
        data = DataWord.from_bytes(b'\x12\x34')
        assert data.payload == 0x1234

    def test_to_bytes(self):
        """Test converting to bytes"""
        data = DataWord(payload=0x1234)
        bytes_out = data.to_bytes()
        assert len(bytes_out) == 3  # 20 bits packed in 3 bytes


class TestWordValidation:
    """Tests for word validation"""

    def test_valid_parity(self):
        """Test parity validation on valid words"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        assert cmd.validate()

    def test_invalid_parity_detection(self):
        """Test detection of invalid parity"""
        cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        corrupted = cmd.corrupt_parity()

        with pytest.raises(ParityException):
            corrupted.validate()

    def test_word_equality(self):
        """Test word equality comparison"""
        cmd1 = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        cmd2 = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
        cmd3 = CommandWord(rt_address=6, transmit_receive=0, subaddress=10, word_count=3)

        assert cmd1 == cmd2
        assert cmd1 != cmd3


def test_word_representations():
    """Test string representations"""
    cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)

    # Test repr
    repr_str = repr(cmd)
    assert "CommandWord" in repr_str
    assert "RT=5" in repr_str

    # Test hex output
    hex_str = cmd.to_hex()
    assert isinstance(hex_str, str)
    assert len(hex_str) == 5

    # Test binary string
    bin_str = cmd.to_binary_string()
    assert isinstance(bin_str, str)
    assert len(bin_str) == 20


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
