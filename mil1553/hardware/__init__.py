"""
Hardware Interface Layer for MIL-STD-1553B

Provides adapters for physical 1553 hardware interfaces.
"""

from mil1553.hardware.base import Hardware1553Interface, TransmitResult, ReceiveResult

__all__ = [
    'Hardware1553Interface',
    'TransmitResult',
    'ReceiveResult',
]
