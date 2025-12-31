"""
Remote Terminal (RT) Simulation

Simulates a MIL-STD-1553B Remote Terminal - subsystem devices that
respond to Bus Controller commands.
"""

from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field
import random

from mil1553.devices.base import Device1553, DeviceType
from mil1553.core.message import Message, MessageType
from mil1553.core.word import CommandWord, StatusWord, DataWord
from mil1553.core.constants import ModeCode, BROADCAST_ADDRESS


@dataclass
class Subaddress:
    """
    RT subaddress configuration.

    Attributes:
        address: Subaddress number (0-31)
        data: Current data stored at this subaddress
        receive_handler: Optional callback for received data
        transmit_handler: Optional callback to generate transmit data
    """
    address: int
    data: List[DataWord] = field(default_factory=list)
    receive_handler: Optional[Callable] = None
    transmit_handler: Optional[Callable] = None


class RemoteTerminal(Device1553):
    """
    Simulated Remote Terminal (RT).

    An RT is a subsystem device on the 1553 bus (e.g., sensor, actuator).
    It:
    - Responds to BC commands
    - Maintains data at subaddresses
    - Reports status via status word
    - Can be in various states (busy, error, etc.)

    Example:
        >>> from mil1553.devices import RemoteTerminal, BusController, VirtualBus
        >>>
        >>> bus = VirtualBus()
        >>> rt = RemoteTerminal(rt_address=5, name="NavSensor")
        >>> bc = BusController()
        >>>
        >>> bus.connect(rt)
        >>> bus.connect(bc)
        >>>
        >>> # Configure RT subaddress
        >>> rt.set_subaddress_data(
        ...     subaddress=10,
        ...     data=[DataWord(payload=0x1234)]
        ... )
        >>>
        >>> # BC can now read from this RT
        >>> response = bc.receive_from_rt(rt_address=5, subaddress=10, word_count=1)
    """

    def __init__(
        self,
        rt_address: int,
        name: Optional[str] = None,
        busy_probability: float = 0.0,
        error_probability: float = 0.0
    ):
        """
        Initialize Remote Terminal.

        Args:
            rt_address: RT address (1-30, 31 is reserved for broadcast)
            name: Optional RT name
            busy_probability: Probability (0-1) of being busy when commanded
            error_probability: Probability (0-1) of reporting error
        """
        if not (1 <= rt_address <= 30):
            raise ValueError(f"RT address must be 1-30, got {rt_address}")

        super().__init__(DeviceType.REMOTE_TERMINAL, name)
        self.rt_address = rt_address
        self.busy_probability = busy_probability
        self.error_probability = error_probability

        # Subaddress storage
        self.subaddresses: Dict[int, Subaddress] = {}
        for i in range(32):
            self.subaddresses[i] = Subaddress(address=i)

        # RT state flags
        self.busy = False
        self.subsystem_flag = False
        self.broadcast_received = False
        self.terminal_flag = False

    def process_message(self, message: Message) -> Optional[Message]:
        """
        Process incoming message from BC.

        Args:
            message: Command from BC

        Returns:
            Response message (status + optional data)
        """
        if not message.command_words:
            return None

        cmd = message.command_words[0]

        # Check if message is for this RT (or broadcast)
        if cmd.rt_address != self.rt_address and cmd.rt_address != BROADCAST_ADDRESS:
            return None

        self.log_message(message, "rx")
        self.statistics.messages_received += 1

        # Handle broadcast (no response)
        if cmd.rt_address == BROADCAST_ADDRESS:
            self._handle_broadcast(cmd, message.data_words)
            return None

        # Handle regular command
        return self._handle_command(cmd, message.data_words)

    def _handle_command(
        self,
        cmd: CommandWord,
        data_words: List[DataWord]
    ) -> Message:
        """Handle regular (non-broadcast) command."""

        # Create status word
        status = self._create_status_word()

        # Mode command
        if cmd.is_mode_command:
            return self._handle_mode_command(cmd, status, data_words)

        # BC-to-RT transfer (receive)
        if cmd.transmit_receive == 0:
            # Store received data
            subaddr = cmd.subaddress
            if subaddr in self.subaddresses:
                self.subaddresses[subaddr].data = data_words.copy()

                # Call receive handler if defined
                if self.subaddresses[subaddr].receive_handler:
                    self.subaddresses[subaddr].receive_handler(data_words)

            response = Message(
                message_type=MessageType.BC_TO_RT,
                command_word=cmd,
                status_word=status
            )

        # RT-to-BC transfer (transmit)
        else:
            subaddr = cmd.subaddress
            transmit_data = []

            if subaddr in self.subaddresses:
                # Call transmit handler if defined
                if self.subaddresses[subaddr].transmit_handler:
                    transmit_data = self.subaddresses[subaddr].transmit_handler()
                else:
                    transmit_data = self.subaddresses[subaddr].data.copy()

            response = Message(
                message_type=MessageType.RT_TO_BC,
                command_word=cmd,
                status_word=status,
                data_words=transmit_data[:cmd.actual_word_count]
            )

        self.log_message(response, "tx")
        self.statistics.messages_sent += 1

        return response

    def _handle_broadcast(self, cmd: CommandWord, data_words: List[DataWord]):
        """Handle broadcast command (no response)."""
        self.broadcast_received = True

        # Store broadcast data
        if cmd.is_mode_command:
            # Broadcast mode command
            pass  # Process but don't respond
        else:
            # Broadcast data transfer
            subaddr = cmd.subaddress
            if subaddr in self.subaddresses:
                self.subaddresses[subaddr].data = data_words.copy()

    def _handle_mode_command(
        self,
        cmd: CommandWord,
        status: StatusWord,
        data_words: List[DataWord]
    ) -> Message:
        """Handle mode command."""
        mode_code = ModeCode(cmd.word_count_mode)

        # Process mode code
        if mode_code == ModeCode.SYNCHRONIZE:
            self.broadcast_received = False

        elif mode_code == ModeCode.TRANSMIT_STATUS_WORD:
            pass  # Just return status

        elif mode_code == ModeCode.RESET_REMOTE_TERMINAL:
            self.reset()

        # Add more mode commands as needed

        return Message(
            message_type=MessageType.MODE_COMMAND,
            command_word=cmd,
            status_word=status,
            data_words=data_words if cmd.transmit_receive else []
        )

    def _create_status_word(self) -> StatusWord:
        """Create status word with current RT state."""

        # Simulate random busy/error states
        message_error = random.random() < self.error_probability
        busy = random.random() < self.busy_probability or self.busy

        return StatusWord(
            rt_address=self.rt_address,
            message_error=message_error,
            instrumentation=False,
            service_request=False,
            reserved=0,
            broadcast_received=self.broadcast_received,
            busy=busy,
            subsystem_flag=self.subsystem_flag,
            dynamic_bus_control=False,
            terminal_flag=self.terminal_flag
        )

    def set_subaddress_data(
        self,
        subaddress: int,
        data: List[DataWord]
    ):
        """
        Set data at a subaddress.

        Args:
            subaddress: Subaddress number (0-31)
            data: Data words to store

        Example:
            >>> rt.set_subaddress_data(
            ...     subaddress=10,
            ...     data=[DataWord(payload=0x1234), DataWord(payload=0x5678)]
            ... )
        """
        if subaddress in self.subaddresses:
            self.subaddresses[subaddress].data = data.copy()

    def get_subaddress_data(self, subaddress: int) -> List[DataWord]:
        """Get data from a subaddress."""
        if subaddress in self.subaddresses:
            return self.subaddresses[subaddress].data.copy()
        return []

    def set_subaddress_handler(
        self,
        subaddress: int,
        receive_handler: Optional[Callable] = None,
        transmit_handler: Optional[Callable] = None
    ):
        """
        Set custom handlers for subaddress operations.

        Args:
            subaddress: Subaddress number
            receive_handler: Called when data is received
            transmit_handler: Called to generate data for transmission

        Example:
            >>> def on_receive(data):
            ...     print(f"Received: {[d.payload for d in data]}")
            >>>
            >>> def on_transmit():
            ...     return [DataWord(payload=sensor.read())]
            >>>
            >>> rt.set_subaddress_handler(
            ...     subaddress=10,
            ...     receive_handler=on_receive,
            ...     transmit_handler=on_transmit
            ... )
        """
        if subaddress in self.subaddresses:
            if receive_handler:
                self.subaddresses[subaddress].receive_handler = receive_handler
            if transmit_handler:
                self.subaddresses[subaddress].transmit_handler = transmit_handler

    def set_busy(self, busy: bool):
        """Set RT busy state."""
        self.busy = busy

    def set_subsystem_flag(self, flag: bool):
        """Set subsystem flag."""
        self.subsystem_flag = flag

    def set_terminal_flag(self, flag: bool):
        """Set terminal flag."""
        self.terminal_flag = flag

    def reset(self):
        """Reset RT to initial state."""
        self.busy = False
        self.subsystem_flag = False
        self.broadcast_received = False
        self.terminal_flag = False
        self.reset_statistics()

        # Clear all subaddress data
        for subaddr in self.subaddresses.values():
            subaddr.data.clear()
