"""
Bus Monitor (BM) Simulation

Simulates a MIL-STD-1553B Bus Monitor - a passive device that observes
all traffic on the bus without participating in transfers.
"""

from typing import Optional, List, Dict, Callable
from dataclasses import dataclass
import time

from mil1553.devices.base import Device1553, DeviceType
from mil1553.core.message import Message
from mil1553.core.word import Word


@dataclass
class CaptureFilter:
    """
    Filter for bus monitoring.

    Attributes:
        rt_addresses: RT addresses to capture (None = all)
        subaddresses: Subaddresses to capture (None = all)
        message_types: Message types to capture (None = all)
        max_messages: Maximum messages to capture (0 = unlimited)
    """
    rt_addresses: Optional[List[int]] = None
    subaddresses: Optional[List[int]] = None
    message_types: Optional[List[str]] = None
    max_messages: int = 0


class BusMonitor(Device1553):
    """
    Simulated Bus Monitor (BM).

    A Bus Monitor passively observes all traffic on the 1553 bus.
    It:
    - Captures all messages without interfering
    - Can filter captures by address, subaddress, or message type
    - Provides analysis capabilities
    - Useful for debugging, validation, and security monitoring

    Example:
        >>> from mil1553.devices import BusMonitor, BusController, RemoteTerminal, VirtualBus
        >>>
        >>> bus = VirtualBus()
        >>> bm = BusMonitor(name="Analyzer")
        >>> bc = BusController()
        >>> rt = RemoteTerminal(rt_address=5)
        >>>
        >>> bus.connect(bm)
        >>> bus.connect(bc)
        >>> bus.connect(rt)
        >>>
        >>> # BM will capture all traffic
        >>> bc.send_to_rt(5, 10, [DataWord(payload=0x1234)])
        >>>
        >>> # Analyze captured traffic
        >>> print(f"Captured {len(bm.captured_messages)} messages")
        >>> for msg in bm.captured_messages:
        ...     print(msg)
    """

    def __init__(
        self,
        name: Optional[str] = None,
        capture_filter: Optional[CaptureFilter] = None
    ):
        """
        Initialize Bus Monitor.

        Args:
            name: Optional BM name
            capture_filter: Optional filter for selective capture
        """
        super().__init__(DeviceType.BUS_MONITOR, name)
        self.capture_filter = capture_filter or CaptureFilter()
        self.captured_messages: List[Message] = []
        self.capture_enabled = True
        self.callbacks: List[Callable] = []

    def process_message(self, message: Message) -> Optional[Message]:
        """
        Process (observe) message on the bus.

        Note: BM never responds to messages - it only observes.

        Args:
            message: Message observed on bus

        Returns:
            None (BM never responds)
        """
        self.statistics.messages_received += 1

        if not self.capture_enabled:
            return None

        # Apply filters
        if not self._should_capture(message):
            return None

        # Capture message
        self.captured_messages.append(message)
        self.log_message(message, "rx")

        # Check max messages limit
        if (self.capture_filter.max_messages > 0 and
            len(self.captured_messages) >= self.capture_filter.max_messages):
            self.capture_enabled = False

        # Call registered callbacks
        for callback in self.callbacks:
            callback(message)

        return None

    def _should_capture(self, message: Message) -> bool:
        """Check if message passes filter."""

        # RT address filter
        if self.capture_filter.rt_addresses is not None:
            if message.command_words:
                rt_addr = message.command_words[0].rt_address
                if rt_addr not in self.capture_filter.rt_addresses:
                    return False

        # Subaddress filter
        if self.capture_filter.subaddresses is not None:
            if message.command_words:
                subaddr = message.command_words[0].subaddress
                if subaddr not in self.capture_filter.subaddresses:
                    return False

        # Message type filter
        if self.capture_filter.message_types is not None:
            if message.message_type.value not in self.capture_filter.message_types:
                return False

        return True

    def set_filter(
        self,
        rt_addresses: Optional[List[int]] = None,
        subaddresses: Optional[List[int]] = None,
        message_types: Optional[List[str]] = None,
        max_messages: int = 0
    ):
        """
        Configure capture filter.

        Args:
            rt_addresses: RT addresses to capture (None = all)
            subaddresses: Subaddresses to capture (None = all)
            message_types: Message types to capture (None = all)
            max_messages: Maximum messages to capture

        Example:
            >>> # Only capture traffic to/from RT 5
            >>> bm.set_filter(rt_addresses=[5])
            >>>
            >>> # Only capture first 100 messages
            >>> bm.set_filter(max_messages=100)
            >>>
            >>> # Capture specific subaddress
            >>> bm.set_filter(rt_addresses=[5, 6], subaddresses=[10, 11])
        """
        self.capture_filter = CaptureFilter(
            rt_addresses=rt_addresses,
            subaddresses=subaddresses,
            message_types=message_types,
            max_messages=max_messages
        )

    def add_callback(self, callback: Callable[[Message], None]):
        """
        Add a callback function to be called for each captured message.

        Args:
            callback: Function that takes a Message as argument

        Example:
            >>> def analyze_message(msg):
            ...     if msg.command_words:
            ...         print(f"RT {msg.command_words[0].rt_address} commanded")
            >>>
            >>> bm.add_callback(analyze_message)
        """
        self.callbacks.append(callback)

    def start_capture(self):
        """Start/resume message capture."""
        self.capture_enabled = True

    def stop_capture(self):
        """Stop message capture."""
        self.capture_enabled = False

    def clear_capture(self):
        """Clear all captured messages."""
        self.captured_messages.clear()

    def get_messages_by_rt(self, rt_address: int) -> List[Message]:
        """
        Get all messages involving a specific RT.

        Args:
            rt_address: RT address to filter

        Returns:
            List of messages involving that RT
        """
        return [
            msg for msg in self.captured_messages
            if msg.command_words and msg.command_words[0].rt_address == rt_address
        ]

    def get_messages_by_subaddress(
        self,
        rt_address: int,
        subaddress: int
    ) -> List[Message]:
        """
        Get all messages to a specific RT/subaddress.

        Args:
            rt_address: RT address
            subaddress: Subaddress

        Returns:
            List of messages to that RT/subaddress
        """
        return [
            msg for msg in self.captured_messages
            if msg.command_words and
            msg.command_words[0].rt_address == rt_address and
            msg.command_words[0].subaddress == subaddress
        ]

    def analyze_traffic(self) -> Dict:
        """
        Analyze captured traffic.

        Returns:
            Dictionary with traffic analysis:
            - total_messages: Total captured
            - rt_activity: Messages per RT
            - subaddress_activity: Messages per subaddress
            - message_types: Breakdown by type
            - average_message_rate: Messages per second
        """
        if not self.captured_messages:
            return {
                'total_messages': 0,
                'rt_activity': {},
                'subaddress_activity': {},
                'message_types': {},
                'average_message_rate': 0
            }

        rt_activity = {}
        subaddress_activity = {}
        message_types = {}

        for msg in self.captured_messages:
            # RT activity
            if msg.command_words:
                rt_addr = msg.command_words[0].rt_address
                rt_activity[rt_addr] = rt_activity.get(rt_addr, 0) + 1

                # Subaddress activity
                subaddr = msg.command_words[0].subaddress
                key = f"RT{rt_addr}:SA{subaddr}"
                subaddress_activity[key] = subaddress_activity.get(key, 0) + 1

            # Message type
            msg_type = msg.message_type.value
            message_types[msg_type] = message_types.get(msg_type, 0) + 1

        # Calculate message rate
        uptime = self.statistics.uptime
        message_rate = len(self.captured_messages) / uptime if uptime > 0 else 0

        return {
            'total_messages': len(self.captured_messages),
            'rt_activity': rt_activity,
            'subaddress_activity': subaddress_activity,
            'message_types': message_types,
            'average_message_rate': message_rate
        }

    def print_analysis(self):
        """Print traffic analysis to console."""
        analysis = self.analyze_traffic()

        print("\n" + "=" * 60)
        print("BUS MONITOR ANALYSIS")
        print("=" * 60)
        print(f"Total Messages: {analysis['total_messages']}")
        print(f"Message Rate: {analysis['average_message_rate']:.2f} msg/s")

        print("\nRT Activity:")
        for rt, count in sorted(analysis['rt_activity'].items()):
            print(f"  RT {rt:2d}: {count:4d} messages")

        print("\nMessage Types:")
        for msg_type, count in analysis['message_types'].items():
            print(f"  {msg_type:20s}: {count:4d} messages")

        print("=" * 60)
