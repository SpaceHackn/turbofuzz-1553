"""MIL-STD-1553B Core Module"""

from mil1553.core.constants import (
    SyncPattern,
    MessageType,
    ModeCode,
    TransmitReceive,
    WordType,
    ErrorType,
    Severity,
    TimingConstants,
    BitMasks,
    BROADCAST_ADDRESS,
    MAX_RT_ADDRESS,
    is_mode_command_subaddress,
    is_broadcast_address,
    is_valid_rt_address,
    word_count_to_actual,
    actual_to_word_count,
)

from mil1553.core.exceptions import (
    MIL1553Exception,
    ProtocolException,
    ParityException,
    SyncException,
    AddressException,
    SubaddressException,
    WordCountException,
    MessageStructureException,
    TimingException,
    ModeCommandException,
    EncodingException,
    ManchesterEncodingException,
    DeviceException,
    SecurityException,
    FuzzingException,
    AttackException,
)

from mil1553.core.word import (
    Word,
    CommandWord,
    StatusWord,
    DataWord,
)

__all__ = [
    # Constants
    'SyncPattern',
    'MessageType',
    'ModeCode',
    'TransmitReceive',
    'WordType',
    'ErrorType',
    'Severity',
    'TimingConstants',
    'BitMasks',
    'BROADCAST_ADDRESS',
    'MAX_RT_ADDRESS',
    'is_mode_command_subaddress',
    'is_broadcast_address',
    'is_valid_rt_address',
    'word_count_to_actual',
    'actual_to_word_count',

    # Exceptions
    'MIL1553Exception',
    'ProtocolException',
    'ParityException',
    'SyncException',
    'AddressException',
    'SubaddressException',
    'WordCountException',
    'MessageStructureException',
    'TimingException',
    'ModeCommandException',
    'EncodingException',
    'ManchesterEncodingException',
    'DeviceException',
    'SecurityException',
    'FuzzingException',
    'AttackException',

    # Words
    'Word',
    'CommandWord',
    'StatusWord',
    'DataWord',
]
