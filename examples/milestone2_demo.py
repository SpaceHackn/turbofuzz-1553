#!/usr/bin/env python3
"""
Milestone 2 Demo: Message Encoding & Decoding Pipeline

This example demonstrates Milestone 2 functionality:
- Creating complete messages (BC-to-RT, RT-to-BC, Mode Commands)
- Manchester II encoding/decoding
- Message validation
- Wire format encoding/decoding
- Round-trip encode/decode verification
"""

from mil1553 import (
    CommandWord, StatusWord, DataWord,
    Message, MessageBuilder, MessageType,
    MessageEncoder, MessageDecoder,
    create_bc_to_rt_message, create_rt_to_bc_message
)
from mil1553.core.validation import ProtocolValidator
from mil1553.core.encoding import ManchesterEncoder


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_subsection(title):
    """Print a subsection header."""
    print(f"\n{title}")
    print("-" * 70)


def main():
    print_section("MIL-STD-1553B Packet Engine - Milestone 2 Demo")

    # ========================================================================
    # 1. Creating Messages
    # ========================================================================
    print_section("1. Creating Messages")

    # BC-to-RT message (simple helper)
    print_subsection("BC-to-RT Message (Helper Function)")
    data_words = [
        DataWord(payload=0x1234),
        DataWord(payload=0x5678),
        DataWord(payload=0x9ABC)
    ]

    msg_bc_to_rt = create_bc_to_rt_message(
        rt_address=5,
        subaddress=10,
        data_words=data_words
    )

    print(f"Message created: {msg_bc_to_rt}")
    print(f"Total words: {msg_bc_to_rt.get_word_count()}")
    print(f"Duration: {msg_bc_to_rt.calculate_message_duration():.2f} μs")

    # RT-to-BC message
    print_subsection("RT-to-BC Message")
    msg_rt_to_bc = create_rt_to_bc_message(
        rt_address=7,
        subaddress=15,
        data_words=[DataWord(payload=0xDEAD), DataWord(payload=0xBEEF)]
    )

    print(f"Message created: {msg_rt_to_bc}")
    print(f"Total words: {msg_rt_to_bc.get_word_count()}")

    # Message Builder (advanced)
    print_subsection("Message Builder Pattern")
    msg_builder = (MessageBuilder()
                   .set_type(MessageType.BC_TO_RT)
                   .add_command(CommandWord(rt_address=12, transmit_receive=0,
                                           subaddress=5, word_count=2))
                   .add_data(DataWord(payload=0xCAFE))
                   .add_data(DataWord(payload=0xBABE))
                   .build())

    print(f"Built message: {msg_builder}")

    # ========================================================================
    # 2. Message Validation
    # ========================================================================
    print_section("2. Message Validation")

    validator = ProtocolValidator(strict=True)

    print_subsection("Validating BC-to-RT Message")
    result = validator.validate_message(msg_bc_to_rt)
    print(f"Validation result: {'PASS' if result.is_valid else 'FAIL'}")
    print(f"Violations: {len(result.violations)}")
    print(f"Warnings: {len(result.warnings)}")

    # Create an invalid message for testing
    print_subsection("Validating Invalid Message")
    cmd_invalid = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
    msg_invalid = Message(
        message_type=MessageType.BC_TO_RT,
        command_word=cmd_invalid,
        data_words=[DataWord(payload=0x1111)]  # Only 1 data word, but command says 3!
    )

    try:
        result_invalid = validator.validate_message(msg_invalid)
        print(f"Validation result: {'PASS' if result_invalid.is_valid else 'FAIL'}")
        if not result_invalid.is_valid:
            for violation in result_invalid.violations:
                print(f"  - {violation}")
    except Exception as e:
        print(f"Validation error: {e}")

    # ========================================================================
    # 3. Encoding to Wire Format
    # ========================================================================
    print_section("3. Encoding to Wire Format")

    # Binary encoding
    print_subsection("Binary Encoding (Simple)")
    encoder_binary = MessageEncoder(encoding="binary", validate=True)
    wire_data_binary, validation_result = encoder_binary.encode(msg_bc_to_rt)

    print(f"Encoded to {len(wire_data_binary)} bytes")
    print(f"Hex: {wire_data_binary.hex()}")
    print(f"Validation: {'PASS' if validation_result.is_valid else 'FAIL'}")

    # Manchester encoding
    print_subsection("Manchester II Encoding")
    encoder_manchester = MessageEncoder(encoding="manchester", validate=True)
    wire_data_manchester, _ = encoder_manchester.encode(msg_bc_to_rt)

    print(f"Encoded to {len(wire_data_manchester)} bytes (Manchester)")
    print(f"Hex (first 20 bytes): {wire_data_manchester[:20].hex()}")

    # Encoding stats
    print_subsection("Encoding Statistics")
    stats = encoder_binary.get_stats(msg_bc_to_rt)
    print(f"Message Type: {stats['message_type']}")
    print(f"Total Words: {stats['total_words']}")
    print(f"  - Command Words: {stats['command_words']}")
    print(f"  - Status Words: {stats['status_words']}")
    print(f"  - Data Words: {stats['data_words']}")
    print(f"Encoded Size: {stats['encoded_bytes']} bytes")
    print(f"Duration: {stats['duration_us']:.2f} μs")
    print(f"Valid: {stats['is_valid']}")

    # ========================================================================
    # 4. Decoding from Wire Format
    # ========================================================================
    print_section("4. Decoding from Wire Format")

    # Binary decoding
    print_subsection("Binary Decoding")
    decoder_binary = MessageDecoder(encoding="binary", validate=True)
    msg_decoded, decode_result = decoder_binary.decode(wire_data_binary, MessageType.BC_TO_RT)

    print(f"Decoded message: {msg_decoded}")
    print(f"Total words: {msg_decoded.get_word_count()}")
    print(f"Data words: {len(msg_decoded.data_words)}")
    for i, data in enumerate(msg_decoded.data_words):
        print(f"  Data[{i}]: {data.payload:#06x}")

    # Manchester decoding
    print_subsection("Manchester Decoding")
    decoder_manchester = MessageDecoder(encoding="manchester", validate=True)
    msg_decoded_manchester, _ = decoder_manchester.decode(wire_data_manchester, MessageType.BC_TO_RT)

    print(f"Decoded message: {msg_decoded_manchester}")
    print(f"Data words: {len(msg_decoded_manchester.data_words)}")

    # ========================================================================
    # 5. Round-Trip Verification
    # ========================================================================
    print_section("5. Round-Trip Verification (Encode → Decode)")

    print_subsection("Binary Encoding Round-Trip")
    # Verify data words match
    original_payloads = [dw.payload for dw in msg_bc_to_rt.data_words]
    decoded_payloads = [dw.payload for dw in msg_decoded.data_words]

    match = original_payloads == decoded_payloads
    print(f"Original payloads: {[hex(p) for p in original_payloads]}")
    print(f"Decoded payloads:  {[hex(p) for p in decoded_payloads]}")
    print(f"Round-trip successful: {match} ✓" if match else f"Round-trip failed: {match} ✗")

    print_subsection("Manchester Encoding Round-Trip")
    decoded_payloads_manchester = [dw.payload for dw in msg_decoded_manchester.data_words]
    match_manchester = original_payloads == decoded_payloads_manchester

    print(f"Original payloads: {[hex(p) for p in original_payloads]}")
    print(f"Decoded payloads:  {[hex(p) for p in decoded_payloads_manchester]}")
    print(f"Round-trip successful: {match_manchester} ✓" if match_manchester else f"Round-trip failed: {match_manchester} ✗")

    # ========================================================================
    # 6. Multiple Message Types
    # ========================================================================
    print_section("6. Encoding Different Message Types")

    print_subsection("Mode Command Message")
    from mil1553 import create_mode_command_message, ModeCode

    msg_mode = create_mode_command_message(
        rt_address=8,
        mode_code=ModeCode.TRANSMIT_STATUS_WORD,
        transmit_receive=1
    )

    wire_mode, _ = encoder_binary.encode(msg_mode)
    print(f"Mode command encoded: {len(wire_mode)} bytes")
    print(f"Message: {msg_mode}")

    print_subsection("Broadcast Message")
    msg_broadcast = create_bc_to_rt_message(
        rt_address=31,  # Broadcast address
        subaddress=10,
        data_words=[DataWord(payload=0xFFFF)]
    )

    wire_broadcast, _ = encoder_binary.encode(msg_broadcast)
    print(f"Broadcast encoded: {len(wire_broadcast)} bytes")
    print(f"Is broadcast: {msg_broadcast.command_words[0].is_broadcast}")

    # ========================================================================
    # 7. Batch Encoding/Decoding
    # ========================================================================
    print_section("7. Batch Operations")

    messages = [msg_bc_to_rt, msg_rt_to_bc, msg_broadcast]

    print_subsection("Batch Encoding")
    encoded_list, results = encoder_binary.encode_batch(messages)

    print(f"Encoded {len(encoded_list)} messages")
    for i, (encoded, result) in enumerate(zip(encoded_list, results)):
        print(f"  Message {i}: {len(encoded)} bytes, valid={result.is_valid if result else 'N/A'}")

    print_subsection("Batch Decoding")
    data_list = [
        (encoded_list[0], MessageType.BC_TO_RT),
        (encoded_list[1], MessageType.RT_TO_BC),
        (encoded_list[2], MessageType.BROADCAST)
    ]

    decoded_list, decode_results = decoder_binary.decode_batch(data_list)
    print(f"Decoded {len([m for m in decoded_list if m is not None])} messages")
    for i, msg in enumerate(decoded_list):
        if msg:
            print(f"  Message {i}: {msg.message_type.value}, {msg.get_word_count()} words")

    # ========================================================================
    # Summary
    # ========================================================================
    print_section("Milestone 2 Complete!")
    print()
    print("✓ Message creation (BC-to-RT, RT-to-BC, Mode Commands)")
    print("✓ Message validation with detailed error reporting")
    print("✓ Binary encoding/decoding")
    print("✓ Manchester II encoding/decoding")
    print("✓ Round-trip encode/decode verification")
    print("✓ Batch operations")
    print("✓ Protocol compliance checking")
    print()
    print("Next: Milestone 3 - Output Formatting (Hex dumps with annotations)")
    print()


if __name__ == "__main__":
    main()
