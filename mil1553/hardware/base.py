"""
Base Hardware Interface for MIL-STD-1553B

Defines the abstract interface that all hardware adapters must implement.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum

from mil1553.core.message import Message
from mil1553.core.word import Word


class DeviceMode(Enum):
    """1553 device operating modes."""
    BUS_CONTROLLER = "bc"
    REMOTE_TERMINAL = "rt"
    BUS_MONITOR = "bm"


class TransmitStatus(Enum):
    """Status of message transmission."""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    NO_RESPONSE = "no_response"
    ERROR = "error"
    BUS_BUSY = "bus_busy"


@dataclass
class TransmitResult:
    """
    Result of transmitting a message on the 1553 bus.

    Attributes:
        status: Transmission status
        message: The message that was transmitted
        response: Response message (if any)
        timestamp: Hardware timestamp (microseconds)
        error_details: Additional error information
    """
    status: TransmitStatus
    message: Message
    response: Optional[Message] = None
    timestamp: Optional[float] = None
    error_details: Optional[str] = None

    @property
    def success(self) -> bool:
        """Whether transmission was successful."""
        return self.status == TransmitStatus.SUCCESS


@dataclass
class ReceiveResult:
    """
    Result of receiving a message from the 1553 bus.

    Attributes:
        message: The received message
        timestamp: Hardware timestamp (microseconds)
        channel: Channel number (for multi-channel devices)
        bus: Bus A or B (for redundant bus)
        signal_quality: Signal quality metrics (if available)
    """
    message: Message
    timestamp: float
    channel: int = 0
    bus: str = "A"
    signal_quality: Optional[Dict[str, Any]] = None


class Hardware1553Interface(ABC):
    """
    Abstract base class for 1553 hardware interfaces.

    All hardware adapters (AltaData, DDC, Excalibur, etc.) should
    implement this interface for compatibility with Turbofuzz-1553.

    Example:
        >>> # Using a hypothetical hardware adapter
        >>> interface = AltaDataAdapter(device_path="/dev/alta0")
        >>> interface.open()
        >>>
        >>> # Generate attack packet
        >>> from turbofuzz_1553.security import Fuzzer, BitFlipFuzzer
        >>> fuzzer = Fuzzer(strategy=BitFlipFuzzer())
        >>> malicious_msg = fuzzer.fuzz_message(legitimate_msg)
        >>>
        >>> # Transmit via hardware
        >>> result = interface.transmit(malicious_msg)
        >>> if result.success:
        ...     print(f"Attack delivered! Response: {result.response}")
        >>>
        >>> interface.close()
    """

    def __init__(
        self,
        device_path: str,
        mode: DeviceMode = DeviceMode.BUS_CONTROLLER
    ):
        """
        Initialize hardware interface.

        Args:
            device_path: Path to hardware device (e.g., "/dev/alta0", "COM1")
            mode: Operating mode (BC, RT, or BM)
        """
        self.device_path = device_path
        self.mode = mode
        self.is_open = False

    @abstractmethod
    def open(self) -> bool:
        """
        Open connection to hardware device.

        Returns:
            True if successful, False otherwise

        Raises:
            HardwareException: If device cannot be opened
        """
        pass

    @abstractmethod
    def close(self) -> bool:
        """
        Close connection to hardware device.

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def transmit(
        self,
        message: Message,
        timeout_us: float = 100
    ) -> TransmitResult:
        """
        Transmit a message on the 1553 bus.

        Args:
            message: Message to transmit
            timeout_us: Timeout in microseconds for response

        Returns:
            TransmitResult with status and response (if any)

        Raises:
            HardwareException: If transmission fails

        Note:
            In BC mode, this sends the command and waits for RT response.
            In RT mode, this queues a response for the next BC command.
            In BM mode, this operation is not supported.
        """
        pass

    @abstractmethod
    def receive(
        self,
        timeout_us: float = 1000,
        count: int = 1
    ) -> List[ReceiveResult]:
        """
        Receive message(s) from the 1553 bus.

        Args:
            timeout_us: Timeout in microseconds
            count: Maximum number of messages to receive

        Returns:
            List of ReceiveResult objects

        Note:
            In BM mode, this captures all bus traffic.
            In RT mode, this receives incoming commands.
            In BC mode, this is typically not used (use transmit() instead).
        """
        pass

    @abstractmethod
    def configure_bc(
        self,
        rt_address: int,
        subaddress: int,
        **kwargs
    ) -> bool:
        """
        Configure Bus Controller settings.

        Args:
            rt_address: Target RT address for BC commands
            subaddress: Target subaddress
            **kwargs: Vendor-specific configuration options

        Returns:
            True if configuration successful
        """
        pass

    @abstractmethod
    def configure_rt(
        self,
        rt_address: int,
        subaddresses: List[int],
        **kwargs
    ) -> bool:
        """
        Configure Remote Terminal settings.

        Args:
            rt_address: This RT's address (1-30)
            subaddresses: Subaddresses to respond to
            **kwargs: Vendor-specific configuration options

        Returns:
            True if configuration successful
        """
        pass

    @abstractmethod
    def configure_bm(
        self,
        filter_addresses: Optional[List[int]] = None,
        **kwargs
    ) -> bool:
        """
        Configure Bus Monitor settings.

        Args:
            filter_addresses: RT addresses to monitor (None = all)
            **kwargs: Vendor-specific configuration options

        Returns:
            True if configuration successful
        """
        pass

    @abstractmethod
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get hardware statistics.

        Returns:
            Dictionary with statistics:
            - messages_transmitted: int
            - messages_received: int
            - errors: int
            - timeouts: int
            - bus_utilization: float (0-100%)
        """
        pass

    @abstractmethod
    def reset(self) -> bool:
        """
        Reset hardware to initial state.

        Returns:
            True if reset successful
        """
        pass

    # Convenience methods

    def transmit_raw(
        self,
        words: List[Word],
        timeout_us: float = 100
    ) -> TransmitResult:
        """
        Transmit raw words directly.

        Useful for fuzzing when you want to send invalid message structures.

        Args:
            words: List of Word objects to transmit
            timeout_us: Timeout in microseconds

        Returns:
            TransmitResult
        """
        # Create a minimal message container
        from mil1553.core.message import Message, MessageType

        msg = Message(
            message_type=MessageType.BC_TO_RT,
            command_words=words[:1] if words else [],
            data_words=words[1:] if len(words) > 1 else []
        )

        return self.transmit(msg, timeout_us)

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


class HardwareException(Exception):
    """Exception raised for hardware-related errors."""
    pass


class HardwareNotAvailableException(HardwareException):
    """Exception raised when hardware is not available."""
    pass


class HardwareTimeoutException(HardwareException):
    """Exception raised when hardware operation times out."""
    pass
