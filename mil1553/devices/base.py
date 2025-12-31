"""
Base Device Classes for MIL-STD-1553B Simulation

Provides abstract base classes for simulated Bus Controller (BC),
Remote Terminal (RT), and Bus Monitor (BM) devices.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time

from mil1553.core.message import Message, MessageType
from mil1553.core.word import CommandWord, StatusWord, DataWord
from mil1553.core.constants import BROADCAST_ADDRESS


class DeviceType(Enum):
    """1553 device types."""
    BUS_CONTROLLER = "BC"
    REMOTE_TERMINAL = "RT"
    BUS_MONITOR = "BM"


@dataclass
class DeviceStatistics:
    """
    Statistics for 1553 device operation.

    Attributes:
        messages_sent: Number of messages transmitted
        messages_received: Number of messages received
        errors: Number of errors encountered
        start_time: Device start timestamp
    """
    messages_sent: int = 0
    messages_received: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def uptime(self) -> float:
        """Device uptime in seconds."""
        return time.time() - self.start_time

    @property
    def message_rate(self) -> float:
        """Messages per second."""
        uptime = self.uptime
        return (self.messages_sent + self.messages_received) / uptime if uptime > 0 else 0


class Device1553(ABC):
    """
    Abstract base class for 1553 devices.

    All simulated devices (BC, RT, BM) inherit from this.
    """

    def __init__(self, device_type: DeviceType, name: Optional[str] = None):
        """
        Initialize 1553 device.

        Args:
            device_type: Type of device (BC, RT, or BM)
            name: Optional device name for identification
        """
        self.device_type = device_type
        self.name = name or f"{device_type.value}-{id(self)}"
        self.statistics = DeviceStatistics()
        self.message_log: List[Message] = []
        self.is_running = False
        self.bus = None  # Will be set when connected to VirtualBus

    @abstractmethod
    def process_message(self, message: Message) -> Optional[Message]:
        """
        Process an incoming message.

        Args:
            message: Incoming message from bus

        Returns:
            Response message (if applicable), None otherwise
        """
        pass

    def log_message(self, message: Message, direction: str = "rx"):
        """
        Log a message for debugging/analysis.

        Args:
            message: Message to log
            direction: "tx" (transmitted) or "rx" (received)
        """
        self.message_log.append(message)

    def get_statistics(self) -> Dict[str, Any]:
        """Get device statistics."""
        return {
            'device_type': self.device_type.value,
            'name': self.name,
            'messages_sent': self.statistics.messages_sent,
            'messages_received': self.statistics.messages_received,
            'errors': self.statistics.errors,
            'uptime': self.statistics.uptime,
            'message_rate': self.statistics.message_rate
        }

    def reset_statistics(self):
        """Reset statistics counters."""
        self.statistics = DeviceStatistics()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name}, type={self.device_type.value})"
