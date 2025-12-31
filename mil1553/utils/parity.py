"""
Parity Calculation Utilities

This module provides parity calculation and validation functions for
MIL-STD-1553B. The protocol uses odd parity, where the parity bit ensures
an odd number of 1s in the word (data + parity).
"""

from mil1553.utils.bitops import count_ones


def calculate_odd_parity(data: int, bit_count: int = 16) -> int:
    """
    Calculate odd parity bit for data.

    MIL-STD-1553B uses odd parity, meaning the total number of 1 bits
    (data + parity) must be odd.

    Args:
        data: The data value to calculate parity for
        bit_count: Number of bits in the data (default 16 for word data field)

    Returns:
        Parity bit (0 or 1)

    Examples:
        >>> calculate_odd_parity(0b0000000000000000, 16)
        1  # 0 ones, need 1 to make odd
        >>> calculate_odd_parity(0b0000000000000001, 16)
        0  # 1 one, already odd
        >>> calculate_odd_parity(0b1111111111111111, 16)
        0  # 16 ones (even), parity 0 makes total 16 (still even without parity)
    """
    ones = count_ones(data, bit_count)
    # For odd parity: if data has even number of 1s, parity = 1; if odd, parity = 0
    return 0 if (ones % 2 == 1) else 1


def calculate_even_parity(data: int, bit_count: int = 16) -> int:
    """
    Calculate even parity bit for data.

    Note: MIL-STD-1553B uses odd parity, but this function is provided
    for completeness and testing purposes.

    Args:
        data: The data value to calculate parity for
        bit_count: Number of bits in the data

    Returns:
        Parity bit (0 or 1)

    Examples:
        >>> calculate_even_parity(0b0000000000000001, 16)
        1  # 1 one, need 1 to make even
        >>> calculate_even_parity(0b0000000000000011, 16)
        0  # 2 ones, already even
    """
    ones = count_ones(data, bit_count)
    return ones % 2


def verify_odd_parity(data: int, parity: int, bit_count: int = 16) -> bool:
    """
    Verify that data and parity bit have odd parity.

    Args:
        data: The data value
        parity: The parity bit (0 or 1)
        bit_count: Number of bits in the data

    Returns:
        True if parity is correct (odd)

    Examples:
        >>> verify_odd_parity(0b0000000000000000, 1, 16)
        True  # 0 + 1 = 1 (odd)
        >>> verify_odd_parity(0b0000000000000001, 0, 16)
        True  # 1 + 0 = 1 (odd)
        >>> verify_odd_parity(0b0000000000000001, 1, 16)
        False  # 1 + 1 = 2 (even)
    """
    total_ones = count_ones(data, bit_count) + (1 if parity else 0)
    return (total_ones % 2) == 1


def verify_even_parity(data: int, parity: int, bit_count: int = 16) -> bool:
    """
    Verify that data and parity bit have even parity.

    Args:
        data: The data value
        parity: The parity bit (0 or 1)
        bit_count: Number of bits in the data

    Returns:
        True if parity is correct (even)
    """
    total_ones = count_ones(data, bit_count) + (1 if parity else 0)
    return (total_ones % 2) == 0


def add_odd_parity(data: int, bit_count: int = 16) -> int:
    """
    Add odd parity bit to data, returning combined value.

    The parity bit is added as the LSB (bit 0).

    Args:
        data: The data value (will be shifted left by 1)
        bit_count: Number of bits in the data

    Returns:
        Combined value: (data << 1) | parity

    Examples:
        >>> hex(add_odd_parity(0x1234, 16))
        '0x2469'  # 0x1234 << 1 | parity
    """
    parity = calculate_odd_parity(data, bit_count)
    return (data << 1) | parity


def add_even_parity(data: int, bit_count: int = 16) -> int:
    """
    Add even parity bit to data, returning combined value.

    The parity bit is added as the LSB (bit 0).

    Args:
        data: The data value (will be shifted left by 1)
        bit_count: Number of bits in the data

    Returns:
        Combined value: (data << 1) | parity
    """
    parity = calculate_even_parity(data, bit_count)
    return (data << 1) | parity


def strip_parity(value: int) -> tuple[int, int]:
    """
    Strip parity bit from a value.

    Assumes parity is in LSB (bit 0) and returns data and parity separately.

    Args:
        value: The value with parity bit in LSB

    Returns:
        Tuple of (data, parity)

    Examples:
        >>> strip_parity(0b100110101)
        (0b10011010, 1)
        >>> strip_parity(0x2468)
        (0x1234, 0)
    """
    parity = value & 1
    data = value >> 1
    return (data, parity)


def corrupt_parity(data: int, current_parity: int) -> int:
    """
    Corrupt (flip) the parity bit.

    Useful for security testing to create parity errors.

    Args:
        data: The data value
        current_parity: Current parity bit

    Returns:
        Flipped parity bit

    Examples:
        >>> corrupt_parity(0x1234, 1)
        0
        >>> corrupt_parity(0x1234, 0)
        1
    """
    return 1 - current_parity


def calculate_word_parity_1553(sync: int, data: int) -> int:
    """
    Calculate parity for a complete MIL-STD-1553B word.

    The parity is calculated over the sync pattern (3 bits) and data field (16 bits).

    Args:
        sync: 3-bit sync pattern
        data: 16-bit data field

    Returns:
        Parity bit (0 or 1)

    Examples:
        >>> calculate_word_parity_1553(0b100, 0x0000)
        0  # 1 one in sync, odd already
        >>> calculate_word_parity_1553(0b000, 0x0000)
        1  # 0 ones, need parity to make odd
    """
    # Combine sync and data
    combined = (sync << 16) | data
    # Calculate parity over 19 bits (3 sync + 16 data)
    return calculate_odd_parity(combined, 19)


def verify_word_parity_1553(sync: int, data: int, parity: int) -> bool:
    """
    Verify parity for a complete MIL-STD-1553B word.

    Args:
        sync: 3-bit sync pattern
        data: 16-bit data field
        parity: Parity bit

    Returns:
        True if parity is correct

    Examples:
        >>> verify_word_parity_1553(0b100, 0x0000, 0)
        True
        >>> verify_word_parity_1553(0b000, 0x0000, 1)
        True
        >>> verify_word_parity_1553(0b000, 0x0000, 0)
        False
    """
    expected_parity = calculate_word_parity_1553(sync, data)
    return parity == expected_parity


def get_parity_error_type(ones_count: int, parity: int, expected_parity_type: str = "odd") -> str:
    """
    Analyze parity error and return description.

    Args:
        ones_count: Number of 1 bits in data
        parity: The parity bit value
        expected_parity_type: "odd" or "even"

    Returns:
        Description of parity status

    Examples:
        >>> get_parity_error_type(5, 0, "odd")
        'Correct (odd parity)'
        >>> get_parity_error_type(4, 0, "odd")
        'Error (even parity, expected odd)'
    """
    total_ones = ones_count + (1 if parity else 0)
    is_odd = (total_ones % 2) == 1

    if expected_parity_type == "odd":
        if is_odd:
            return "Correct (odd parity)"
        else:
            return "Error (even parity, expected odd)"
    else:  # even
        if is_odd:
            return "Error (odd parity, expected even)"
        else:
            return "Correct (even parity)"


# Lookup table for fast parity calculation (optional optimization)
# Pre-computed parity for all 8-bit values
_PARITY_TABLE_8BIT = [
    calculate_odd_parity(i, 8) for i in range(256)
]


def calculate_odd_parity_fast(data: int, bit_count: int = 16) -> int:
    """
    Fast odd parity calculation using lookup table.

    For larger data sizes, breaks into 8-bit chunks and uses table lookup.
    Generally faster for repeated calculations.

    Args:
        data: The data value
        bit_count: Number of bits in the data

    Returns:
        Parity bit (0 or 1)
    """
    # For 16-bit data, split into two 8-bit chunks
    if bit_count == 16:
        low_byte = data & 0xFF
        high_byte = (data >> 8) & 0xFF
        parity_low = _PARITY_TABLE_8BIT[low_byte]
        parity_high = _PARITY_TABLE_8BIT[high_byte]
        # XOR the parities (if both even or both odd, result is even -> parity 1)
        return 1 if (parity_low == parity_high) else 0
    else:
        # Fall back to standard calculation for other bit widths
        return calculate_odd_parity(data, bit_count)
