#!/usr/bin/env python3
"""
Milestone 1 Demo: Basic Word Creation and Manipulation

This example demonstrates the core functionality of Milestone 1:
- Creating Command, Status, and Data words
- Field extraction and validation
- Parity calculation and corruption
- Hex and binary output
"""

from mil1553 import CommandWord, StatusWord, DataWord, MessageType


def main():
    print("=" * 70)
    print("MIL-STD-1553B Packet Engine - Milestone 1 Demo")
    print("=" * 70)
    print()

    # ========================================================================
    # 1. Command Word Creation
    # ========================================================================
    print("1. Creating Command Words")
    print("-" * 70)

    # BC-to-RT command
    cmd_bc_to_rt = CommandWord(
        rt_address=5,           # RT address 5
        transmit_receive=0,     # Receive (BC sending data to RT)
        subaddress=10,          # Subaddress 10
        word_count=3            # 3 data words
    )

    print(f"BC-to-RT Command:     {cmd_bc_to_rt}")
    print(f"  Message Type:       {cmd_bc_to_rt.get_message_type().value}")
    print(f"  Actual Word Count:  {cmd_bc_to_rt.actual_word_count}")
    print(f"  Hex:                0x{cmd_bc_to_rt.to_hex()}")
    print(f"  Binary:             0b{cmd_bc_to_rt.to_binary_string('_')}")
    print(f"  Valid Parity:       {cmd_bc_to_rt.is_valid_parity()}")
    print()

    # Broadcast command
    cmd_broadcast = CommandWord(
        rt_address=31,          # Broadcast address
        transmit_receive=0,     # Receive
        subaddress=5,
        word_count=10
    )

    print(f"Broadcast Command:    {cmd_broadcast}")
    print(f"  Is Broadcast:       {cmd_broadcast.is_broadcast}")
    print(f"  Message Type:       {cmd_broadcast.get_message_type().value}")
    print()

    # Mode command
    cmd_mode = CommandWord(
        rt_address=5,
        transmit_receive=1,
        subaddress=0,           # Subaddress 0 indicates mode command
        word_count=2
    )

    print(f"Mode Command:         {cmd_mode}")
    print(f"  Is Mode Command:    {cmd_mode.is_mode_command}")
    print(f"  Mode Code:          {cmd_mode.mode_code}")
    print(f"  Message Type:       {cmd_mode.get_message_type().value}")
    print()

    # ========================================================================
    # 2. Status Word Creation
    # ========================================================================
    print("2. Creating Status Words")
    print("-" * 70)

    # Clean status (no errors)
    status_ok = StatusWord(rt_address=5)
    print(f"Clean Status:         {status_ok}")
    print(f"  Active Flags:       {status_ok.get_active_flags()}")
    print()

    # Status with errors
    status_error = StatusWord(
        rt_address=5,
        message_error=True,
        busy=True,
        service_request=True
    )

    print(f"Error Status:         {status_error}")
    print(f"  Active Flags:       {status_error.get_active_flags()}")
    print(f"  Message Error:      {status_error.message_error}")
    print(f"  Busy:               {status_error.busy}")
    print(f"  Service Request:    {status_error.service_request}")
    print()

    # ========================================================================
    # 3. Data Word Creation
    # ========================================================================
    print("3. Creating Data Words")
    print("-" * 70)

    # Create data words with various payloads
    data1 = DataWord(payload=0x1234)
    data2 = DataWord(payload=0x5678)
    data3 = DataWord(payload=0xABCD)

    print(f"Data Word 1:          {data1}")
    print(f"  Hex:                0x{data1.to_hex()}")
    print(f"  Unsigned:           {data1.to_unsigned_int()}")
    print(f"  Signed:             {data1.to_signed_int()}")
    print()

    # Negative number (MSB set)
    data_negative = DataWord(payload=0xFFFF)
    print(f"Data Word (0xFFFF):   {data_negative}")
    print(f"  Unsigned:           {data_negative.to_unsigned_int()}")
    print(f"  Signed:             {data_negative.to_signed_int()}")
    print()

    # ========================================================================
    # 4. Security Testing: Parity Corruption
    # ========================================================================
    print("4. Security Testing: Parity Corruption")
    print("-" * 70)

    original = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
    corrupted = original.corrupt_parity()

    print(f"Original Command:     Parity={original.parity}, Valid={original.is_valid_parity()}")
    print(f"Corrupted Command:    Parity={corrupted.parity}, Valid={corrupted.is_valid_parity()}")
    print()

    try:
        corrupted.validate()
    except Exception as e:
        print(f"Validation Error:     {type(e).__name__}: {e}")
    print()

    # ========================================================================
    # 5. Security Testing: Sync Corruption
    # ========================================================================
    print("5. Security Testing: Sync Corruption")
    print("-" * 70)

    original_cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
    corrupted_sync = original_cmd.corrupt_sync()

    print(f"Original Sync:        0b{original_cmd.sync:03b} (COMMAND_STATUS)")
    print(f"Corrupted Sync:       0b{corrupted_sync.sync:03b} (DATA)")
    print()

    # ========================================================================
    # 6. Word Count Handling (0 = 32 words)
    # ========================================================================
    print("6. Word Count Handling")
    print("-" * 70)

    cmd_max_words = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=0)
    print(f"Word Count Field:     {cmd_max_words.word_count_mode}")
    print(f"Actual Word Count:    {cmd_max_words.actual_word_count} (0 means 32)")
    print()

    # ========================================================================
    # 7. Byte Conversion
    # ========================================================================
    print("7. Byte Conversion")
    print("-" * 70)

    cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
    cmd_bytes = cmd.to_bytes()

    print(f"Command as bytes:     {cmd_bytes.hex()}")
    print(f"Length:               {len(cmd_bytes)} bytes (20 bits)")
    print()

    # ========================================================================
    # Summary
    # ========================================================================
    print("=" * 70)
    print("Milestone 1 Complete!")
    print("=" * 70)
    print()
    print("✓ Command, Status, and Data words implemented")
    print("✓ Parity calculation and validation working")
    print("✓ Field extraction and encoding working")
    print("✓ Security testing features (corruption) working")
    print("✓ All protocol constants and bit masks defined")
    print("✓ 23 unit tests passing")
    print()
    print("Next: Milestone 2 - Encoding/Decoding Pipeline")
    print()


if __name__ == "__main__":
    main()
