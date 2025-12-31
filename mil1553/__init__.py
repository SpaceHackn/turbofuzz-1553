"""
MIL-STD-1553B Security Testing Packet Engine

A comprehensive Python packet engine for MIL-STD-1553B security testing,
supporting protocol-compliant packet generation, parsing, fuzzing, and attack simulation.
"""

__version__ = "0.1.0"

# Import core classes for convenience
from mil1553.core import (
    CommandWord,
    StatusWord,
    DataWord,
    MessageType,
    ModeCode,
    SyncPattern,
    TransmitReceive,
)

from mil1553.core.message import (
    Message,
    MessageBuilder,
    create_bc_to_rt_message,
    create_rt_to_bc_message,
    create_mode_command_message,
)

from mil1553.parser import (
    MessageEncoder,
    MessageDecoder,
)

__all__ = [
    # Words
    'CommandWord',
    'StatusWord',
    'DataWord',

    # Enums
    'MessageType',
    'ModeCode',
    'SyncPattern',
    'TransmitReceive',

    # Messages
    'Message',
    'MessageBuilder',
    'create_bc_to_rt_message',
    'create_rt_to_bc_message',
    'create_mode_command_message',

    # Encoding/Decoding
    'MessageEncoder',
    'MessageDecoder',
]
