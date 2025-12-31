"""
Bit Manipulation Utilities

This module provides low-level bit manipulation functions used throughout
the MIL-STD-1553B packet engine. These functions handle extraction, insertion,
rotation, and analysis of bits within words.
"""

from typing import Union


def extract_bits(value: int, start: int, length: int) -> int:
    """
    Extract a range of bits from a value.

    Bits are numbered from LSB (bit 0) to MSB.

    Args:
        value: The value to extract bits from
        start: Starting bit position (LSB = 0)
        length: Number of bits to extract

    Returns:
        Extracted bits as an integer

    Examples:
        >>> extract_bits(0b11010110, 2, 4)
        0b0101  # Extracted bits 2-5
        >>> extract_bits(0x1A3C, 8, 8)
        0x1A  # Extract upper byte
    """
    mask = (1 << length) - 1
    return (value >> start) & mask


def set_bits(value: int, bits: int, start: int, length: int) -> int:
    """
    Set a range of bits in a value.

    Args:
        value: The original value
        bits: The bits to insert
        start: Starting bit position (LSB = 0)
        length: Number of bits to set

    Returns:
        Value with bits set

    Examples:
        >>> set_bits(0b00000000, 0b1111, 2, 4)
        0b00111100
        >>> set_bits(0xFF00, 0x34, 0, 8)
        0xFF34
    """
    mask = ((1 << length) - 1) << start
    bits_shifted = (bits << start) & mask
    return (value & ~mask) | bits_shifted


def get_bit(value: int, position: int) -> int:
    """
    Get the value of a single bit.

    Args:
        value: The value to check
        position: Bit position (LSB = 0)

    Returns:
        0 or 1

    Examples:
        >>> get_bit(0b10110, 2)
        1
        >>> get_bit(0b10110, 0)
        0
    """
    return (value >> position) & 1


def flip_bit(value: int, position: int) -> int:
    """
    Flip (toggle) a single bit.

    Args:
        value: The original value
        position: Bit position to flip (LSB = 0)

    Returns:
        Value with bit flipped

    Examples:
        >>> flip_bit(0b10110, 0)
        0b10111
        >>> flip_bit(0b10110, 2)
        0b10010
    """
    return value ^ (1 << position)


def set_bit(value: int, position: int, bit_value: int) -> int:
    """
    Set a single bit to a specific value (0 or 1).

    Args:
        value: The original value
        position: Bit position (LSB = 0)
        bit_value: Value to set (0 or 1)

    Returns:
        Value with bit set

    Examples:
        >>> set_bit(0b10110, 0, 1)
        0b10111
        >>> set_bit(0b10110, 2, 0)
        0b10010
    """
    if bit_value:
        return value | (1 << position)
    else:
        return value & ~(1 << position)


def count_ones(value: int, width: int = None) -> int:
    """
    Count the number of 1 bits in a value.

    Args:
        value: The value to count bits in
        width: Optional bit width to limit counting (counts all bits if None)

    Returns:
        Number of 1 bits

    Examples:
        >>> count_ones(0b10110110)
        5
        >>> count_ones(0xFF, 8)
        8
    """
    if width is not None:
        value &= (1 << width) - 1

    count = 0
    while value:
        count += value & 1
        value >>= 1
    return count


def count_zeros(value: int, width: int) -> int:
    """
    Count the number of 0 bits in a value.

    Args:
        value: The value to count bits in
        width: Bit width to consider

    Returns:
        Number of 0 bits

    Examples:
        >>> count_zeros(0b10110110, 8)
        3
    """
    return width - count_ones(value, width)


def rotate_left(value: int, shift: int, width: int) -> int:
    """
    Rotate bits left (circular shift).

    Args:
        value: The value to rotate
        shift: Number of positions to rotate
        width: Bit width of the value

    Returns:
        Rotated value

    Examples:
        >>> rotate_left(0b10110, 2, 5)
        0b11010
        >>> rotate_left(0x12, 4, 8)
        0x21
    """
    shift %= width
    mask = (1 << width) - 1
    value &= mask
    return ((value << shift) | (value >> (width - shift))) & mask


def rotate_right(value: int, shift: int, width: int) -> int:
    """
    Rotate bits right (circular shift).

    Args:
        value: The value to rotate
        shift: Number of positions to rotate
        width: Bit width of the value

    Returns:
        Rotated value

    Examples:
        >>> rotate_right(0b10110, 2, 5)
        0b10101
        >>> rotate_right(0x12, 4, 8)
        0x21
    """
    shift %= width
    mask = (1 << width) - 1
    value &= mask
    return ((value >> shift) | (value << (width - shift))) & mask


def reverse_bits(value: int, width: int) -> int:
    """
    Reverse the bit order of a value.

    Args:
        value: The value to reverse
        width: Bit width

    Returns:
        Bit-reversed value

    Examples:
        >>> reverse_bits(0b10110, 5)
        0b01101
        >>> reverse_bits(0x12, 8)
        0x48
    """
    result = 0
    for i in range(width):
        if value & (1 << i):
            result |= 1 << (width - 1 - i)
    return result


def sign_extend(value: int, from_width: int, to_width: int) -> int:
    """
    Sign-extend a value from one width to another.

    Args:
        value: The value to extend
        from_width: Original bit width
        to_width: Target bit width

    Returns:
        Sign-extended value

    Examples:
        >>> sign_extend(0b1111, 4, 8)  # Negative 4-bit number
        0b11111111  # Extended to 8 bits
        >>> sign_extend(0b0111, 4, 8)  # Positive 4-bit number
        0b00000111  # Extended to 8 bits
    """
    sign_bit = 1 << (from_width - 1)
    if value & sign_bit:
        # Negative - extend with 1s
        extension_mask = ((1 << to_width) - 1) ^ ((1 << from_width) - 1)
        return value | extension_mask
    else:
        # Positive - just mask to ensure clean result
        return value & ((1 << from_width) - 1)


def is_power_of_two(value: int) -> bool:
    """
    Check if a value is a power of two.

    Args:
        value: The value to check

    Returns:
        True if value is a power of two

    Examples:
        >>> is_power_of_two(16)
        True
        >>> is_power_of_two(15)
        False
    """
    return value > 0 and (value & (value - 1)) == 0


def next_power_of_two(value: int) -> int:
    """
    Find the next power of two greater than or equal to value.

    Args:
        value: The input value

    Returns:
        Next power of two

    Examples:
        >>> next_power_of_two(15)
        16
        >>> next_power_of_two(16)
        16
    """
    if value <= 0:
        return 1

    value -= 1
    value |= value >> 1
    value |= value >> 2
    value |= value >> 4
    value |= value >> 8
    value |= value >> 16
    value |= value >> 32
    return value + 1


def to_binary_string(value: int, width: int, separator: str = "") -> str:
    """
    Convert a value to a binary string with specified width.

    Args:
        value: The value to convert
        width: Bit width (pads with leading zeros)
        separator: Optional separator (e.g., "_" or " ") every 4 bits

    Returns:
        Binary string representation

    Examples:
        >>> to_binary_string(0b10110, 8)
        '00010110'
        >>> to_binary_string(0xFF, 8, "_")
        '1111_1111'
    """
    binary = format(value & ((1 << width) - 1), f'0{width}b')

    if separator:
        # Add separator every 4 bits (nibble)
        chunks = [binary[i:i+4] for i in range(0, len(binary), 4)]
        return separator.join(chunks)

    return binary


def from_binary_string(binary_str: str) -> int:
    """
    Convert a binary string to an integer.

    Handles strings with separators (spaces, underscores).

    Args:
        binary_str: Binary string (e.g., "1011" or "10_11" or "10 11")

    Returns:
        Integer value

    Examples:
        >>> from_binary_string("10110")
        22
        >>> from_binary_string("1111_1111")
        255
    """
    # Remove common separators
    clean = binary_str.replace("_", "").replace(" ", "").replace("0b", "")
    return int(clean, 2)


def to_hex_string(value: int, width: int) -> str:
    """
    Convert a value to a hexadecimal string with specified bit width.

    Args:
        value: The value to convert
        width: Bit width (determines hex digit count)

    Returns:
        Hexadecimal string (without 0x prefix)

    Examples:
        >>> to_hex_string(0x1A3C, 16)
        '1A3C'
        >>> to_hex_string(0xFF, 8)
        'FF'
    """
    hex_digits = (width + 3) // 4  # Round up to nearest hex digit
    return format(value & ((1 << width) - 1), f'0{hex_digits}X')


def mask_for_width(width: int) -> int:
    """
    Create a bit mask for a given width.

    Args:
        width: Number of bits

    Returns:
        Mask with 'width' bits set to 1

    Examples:
        >>> mask_for_width(8)
        0xFF
        >>> mask_for_width(16)
        0xFFFF
    """
    return (1 << width) - 1


def pack_fields(**fields: dict) -> int:
    """
    Pack multiple bit fields into a single value.

    Each field is specified as name=(value, start, length).

    Args:
        **fields: Field specifications

    Returns:
        Packed value

    Examples:
        >>> pack_fields(a=(0b111, 0, 3), b=(0b1010, 3, 4))
        0b1010111
    """
    result = 0
    for name, (value, start, length) in fields.items():
        result = set_bits(result, value, start, length)
    return result


def unpack_fields(value: int, **field_specs: dict) -> dict:
    """
    Unpack multiple bit fields from a single value.

    Each field is specified as name=(start, length).

    Args:
        value: The value to unpack
        **field_specs: Field specifications

    Returns:
        Dictionary of field names to values

    Examples:
        >>> unpack_fields(0b1010111, a=(0, 3), b=(3, 4))
        {'a': 7, 'b': 10}
    """
    result = {}
    for name, (start, length) in field_specs.items():
        result[name] = extract_bits(value, start, length)
    return result
