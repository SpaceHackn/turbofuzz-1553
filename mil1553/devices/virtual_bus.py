"""
Virtual 1553 Bus Simulation

Simulates a MIL-STD-1553B bus in software, allowing BC, RT, and BM
devices to communicate without physical hardware.
"""

from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
import time
import threading
from queue import Queue, Empty

from mil1553.core.message import Message
from mil1553.core.constants import TimingConstants
from mil1553.devices.base import Device1553, DeviceType


@dataclass
class BusMessage:
    """
    Message on the virtual bus.

    Attributes:
        message: The 1553 message
        timestamp: When message was transmitted (microseconds)
        source: Device that transmitted the message
    """
    message: Message
    timestamp: float
    source: str


class VirtualBus:
    """
    Simulated MIL-STD-1553B bus.

    Provides a software simulation of the 1553 bus, including:
    - Message transmission with timing
    - Device connectivity
    - Bus monitoring
    - Collision detection (optional)

    Example:
        >>> bus = VirtualBus()
        >>> bc = BusController()
        >>> rt = RemoteTerminal(rt_address=5)
        >>> bm = BusMonitor()
        >>>
        >>> bus.connect(bc)
        >>> bus.connect(rt)
        >>> bus.connect(bm)
        >>>
        >>> # BC sends command, RT responds, BM observes
        >>> bus.start()
    """

    def __init__(self, simulate_timing: bool = True):
        """
        Initialize virtual bus.

        Args:
            simulate_timing: Whether to simulate real-world timing delays
        """
        self.simulate_timing = simulate_timing
        self.devices: Dict[str, Device1553] = {}
        self.message_queue: Queue = Queue()
        self.message_history: List[BusMessage] = []
        self.is_running = False
        self._lock = threading.Lock()

    def connect(self, device: Device1553) -> bool:
        """
        Connect a device to the bus.

        Args:
            device: Device to connect (BC, RT, or BM)

        Returns:
            True if connected successfully
        """
        with self._lock:
            if device.name in self.devices:
                return False

            self.devices[device.name] = device
            device.bus = self
            return True

    def disconnect(self, device: Device1553) -> bool:
        """
        Disconnect a device from the bus.

        Args:
            device: Device to disconnect

        Returns:
            True if disconnected successfully
        """
        with self._lock:
            if device.name in self.devices:
                del self.devices[device.name]
                device.bus = None
                return True
            return False

    def transmit(
        self,
        message: Message,
        source: Device1553,
        wait_for_response: bool = True
    ) -> Optional[Message]:
        """
        Transmit a message on the bus.

        Args:
            message: Message to transmit
            source: Device transmitting the message
            wait_for_response: Whether to wait for RT response (BC mode)

        Returns:
            Response message (if applicable), None otherwise

        Note:
            Only BC should transmit commands. RT transmits status/data
            in response to BC commands.
        """
        timestamp = time.time() * 1e6  # Microseconds

        # Add to history
        bus_msg = BusMessage(
            message=message,
            timestamp=timestamp,
            source=source.name
        )

        with self._lock:
            self.message_history.append(bus_msg)

        # Simulate message transmission time
        if self.simulate_timing:
            msg_duration = message.calculate_message_duration()
            time.sleep(msg_duration / 1e6)  # Convert to seconds

        # Deliver to all devices except source
        response = None
        with self._lock:
            for device_name, device in self.devices.items():
                if device_name == source.name:
                    continue

                # Bus Monitors receive everything
                if device.device_type == DeviceType.BUS_MONITOR:
                    device.process_message(message)

                # RTs process messages addressed to them
                elif device.device_type == DeviceType.REMOTE_TERMINAL:
                    resp = device.process_message(message)
                    if resp and wait_for_response:
                        response = resp

        # Simulate response time
        if response and self.simulate_timing:
            time.sleep(TimingConstants.RESPONSE_TIME_TYPICAL / 1e6)

        return response

    def get_devices(self, device_type: Optional[DeviceType] = None) -> List[Device1553]:
        """
        Get connected devices.

        Args:
            device_type: Filter by device type (None = all)

        Returns:
            List of devices
        """
        with self._lock:
            devices = list(self.devices.values())

        if device_type:
            devices = [d for d in devices if d.device_type == device_type]

        return devices

    def get_statistics(self) -> Dict:
        """Get bus statistics."""
        with self._lock:
            total_messages = len(self.message_history)
            device_count = len(self.devices)

            device_breakdown = {}
            for dtype in DeviceType:
                count = len([d for d in self.devices.values() if d.device_type == dtype])
                device_breakdown[dtype.value] = count

        return {
            'total_messages': total_messages,
            'device_count': device_count,
            'devices_by_type': device_breakdown,
            'is_running': self.is_running
        }

    def clear_history(self):
        """Clear message history."""
        with self._lock:
            self.message_history.clear()

    def start(self):
        """Start bus operation."""
        self.is_running = True
        for device in self.devices.values():
            device.is_running = True

    def stop(self):
        """Stop bus operation."""
        self.is_running = False
        for device in self.devices.values():
            device.is_running = False

    def __repr__(self) -> str:
        return f"VirtualBus(devices={len(self.devices)}, messages={len(self.message_history)})"
