#!/usr/bin/env python3
"""
Milestone 3 Demo: Output Formatting

This example demonstrates Milestone 3 functionality:
- Binary formatter (raw bytes)
- Hex dump formatter
- Annotated hex formatter (with field descriptions)
- Compact formatter (one-line logging)
- Visual formatter (ASCII art)
- JSON formatter (programmatic processing)
"""

from mil1553 import (
    CommandWord, StatusWord, DataWord,
    create_bc_to_rt_message, create_rt_to_bc_message,
    create_mode_command_message, MessageType, ModeCode
)
from mil1553.output import (
    BinaryFormatter,
    HexFormatter,
    AnnotatedHexFormatter,
    CompactHexFormatter,
    VisualFormatter,
    JSONFormatter,
    get_formatter
)


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    print_section("MIL-STD-1553B Packet Engine - Milestone 3 Demo")
    print("\nOutput Formatting & Visualization\n")

    # ========================================================================
    # Create Sample Messages
    # ========================================================================
    print_section("Sample Messages")

    # BC-to-RT message
    msg_bc_to_rt = create_bc_to_rt_message(
        rt_address=5,
        subaddress=10,
        data_words=[
            DataWord(payload=0x1234),
            DataWord(payload=0x5678),
            DataWord(payload=0x9ABC),
            DataWord(payload=0xDEF0)
        ]
    )
    print("Created BC-to-RT message with 4 data words")

    # RT-to-BC message with status
    msg_rt_to_bc = create_rt_to_bc_message(
        rt_address=7,
        subaddress=15,
        data_words=[DataWord(payload=0xCAFE), DataWord(payload=0xBABE)],
        status_word=StatusWord(rt_address=7, message_error=False, busy=False)
    )
    print("Created RT-to-BC message with status word")

    # Mode command
    msg_mode = create_mode_command_message(
        rt_address=8,
        mode_code=ModeCode.TRANSMIT_STATUS_WORD,
        transmit_receive=1
    )
    print("Created Mode Command message")

    # ========================================================================
    # 1. Binary Formatter (Raw Bytes)
    # ========================================================================
    print_section("1. Binary Formatter - Raw Bytes")

    binary_fmt = BinaryFormatter()

    print("\nBC-to-RT Message (Binary):")
    print(binary_fmt.format_message(msg_bc_to_rt))

    print("\nSingle Command Word (Binary):")
    cmd = msg_bc_to_rt.command_words[0]
    print(binary_fmt.format_word(cmd))

    # ========================================================================
    # 2. Hex Dump Formatter
    # ========================================================================
    print_section("2. Hex Dump Formatter - Traditional Hex Output")

    hex_fmt = HexFormatter(bytes_per_line=16, show_ascii=True)

    print("\nBC-to-RT Message (Hex Dump):")
    print(hex_fmt.format_message(msg_bc_to_rt))

    print("\nRT-to-BC Message (Hex Dump):")
    print(hex_fmt.format_message(msg_rt_to_bc))

    # ========================================================================
    # 3. Annotated Hex Formatter (MOST USEFUL FOR SECURITY TESTING)
    # ========================================================================
    print_section("3. Annotated Hex Formatter - Field Descriptions")

    annotated_fmt = AnnotatedHexFormatter(show_binary=True, show_parity=True)

    print("\nBC-to-RT Message (Annotated):")
    print(annotated_fmt.format_message(msg_bc_to_rt))

    print("\n" + "-" * 70)
    print("\nMode Command Message (Annotated):")
    print(annotated_fmt.format_message(msg_mode))

    # ========================================================================
    # 4. Compact Formatter (One-Line Logging)
    # ========================================================================
    print_section("4. Compact Formatter - One-Line Output")

    compact_fmt = CompactHexFormatter()

    print("\nBC-to-RT Message (Compact):")
    print(compact_fmt.format_message(msg_bc_to_rt))

    print("\nRT-to-BC Message (Compact):")
    print(compact_fmt.format_message(msg_rt_to_bc))

    print("\nMode Command (Compact):")
    print(compact_fmt.format_message(msg_mode))

    print("\n\nCompact format is ideal for logs:")
    print("  - Easy to grep/search")
    print("  - Shows key fields at a glance")
    print("  - Minimal space usage")

    # ========================================================================
    # 5. Visual Formatter (ASCII Art)
    # ========================================================================
    print_section("5. Visual Formatter - ASCII Art Visualization")

    visual_fmt = VisualFormatter()

    print("\nCommand Word (Visual):")
    cmd = msg_bc_to_rt.command_words[0]
    print(visual_fmt.format_word(cmd))

    print("\nStatus Word (Visual):")
    status = msg_rt_to_bc.status_words[0]
    print(visual_fmt.format_word(status))

    print("\nData Word (Visual):")
    data = msg_bc_to_rt.data_words[0]
    print(visual_fmt.format_word(data))

    print("\n\nComplete Message (Visual):")
    print(visual_fmt.format_message(msg_mode))

    # ========================================================================
    # 6. JSON Formatter (Programmatic)
    # ========================================================================
    print_section("6. JSON Formatter - Machine-Readable Output")

    json_fmt = JSONFormatter()

    print("\nCommand Word (JSON):")
    print(json_fmt.format_word(cmd))

    print("\nComplete Message (JSON):")
    print(json_fmt.format_message(msg_bc_to_rt))

    # ========================================================================
    # 7. Formatter Factory
    # ========================================================================
    print_section("7. Using the Formatter Factory")

    print("\nCreate formatters dynamically:")

    # Get annotated formatter
    fmt1 = get_formatter("annotated", show_binary=False, show_parity=True)
    print("\nAnnotated (no binary):")
    print(fmt1.format_word(cmd))

    # Get compact formatter
    fmt2 = get_formatter("compact")
    print("\nCompact:")
    print(fmt2.format_word(cmd))

    # ========================================================================
    # 8. Security Testing Use Case
    # ========================================================================
    print_section("8. Security Testing Use Case - Analyzing Corrupted Packets")

    print("\nOriginal Command Word:")
    original = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=3)
    print(annotated_fmt.format_word(original))

    print("\n" + "-" * 70)
    print("\nCorrupted Parity:")
    corrupted_parity = original.corrupt_parity()
    print(annotated_fmt.format_word(corrupted_parity))

    print("\n" + "-" * 70)
    print("\nCorrupted Sync:")
    corrupted_sync = original.corrupt_sync()
    print(annotated_fmt.format_word(corrupted_sync))

    # ========================================================================
    # 9. Batch Formatting
    # ========================================================================
    print_section("9. Batch Formatting Multiple Messages")

    messages = [msg_bc_to_rt, msg_rt_to_bc, msg_mode]

    print("\nCompact format for all messages:")
    for i, msg in enumerate(messages):
        print(f"{i}: {compact_fmt.format_message(msg)}")

    # ========================================================================
    # 10. Comparison of All Formats
    # ========================================================================
    print_section("10. Format Comparison - Same Message, Different Views")

    test_msg = create_bc_to_rt_message(
        rt_address=12,
        subaddress=7,
        data_words=[DataWord(payload=0xAAAA), DataWord(payload=0x5555)]
    )

    formats = {
        "Binary": BinaryFormatter(),
        "Hex": HexFormatter(),
        "Annotated": AnnotatedHexFormatter(show_binary=False),
        "Compact": CompactHexFormatter(),
        "JSON": JSONFormatter()
    }

    for name, formatter in formats.items():
        print(f"\n{name} Format:")
        print("-" * 70)
        output = formatter.format_message(test_msg)
        # Truncate long outputs
        if len(output) > 500:
            print(output[:500] + "\n... (truncated)")
        else:
            print(output)

    # ========================================================================
    # Summary
    # ========================================================================
    print_section("Milestone 3 Complete!")
    print()
    print("Available Output Formats:")
    print("  ✓ Binary         - Raw bytes for transmission/storage")
    print("  ✓ Hex Dump       - Traditional hex dump with ASCII")
    print("  ✓ Annotated Hex  - Hex with detailed field annotations")
    print("  ✓ Compact        - One-line format for logging")
    print("  ✓ Visual         - ASCII art visualization")
    print("  ✓ JSON           - Machine-readable structured data")
    print()
    print("Use Cases:")
    print("  • Security Testing: Annotated format shows field manipulations")
    print("  • Debugging: Visual format provides clear packet structure")
    print("  • Logging: Compact format for efficient log storage")
    print("  • Analysis: JSON format for automated processing")
    print("  • Documentation: Annotated/Visual for reports")
    print()
    print("Next: Milestone 4 - Device Simulation (BC, RT, BM)")
    print()


if __name__ == "__main__":
    main()
