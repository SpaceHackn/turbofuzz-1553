"""
Bus Controller (BC) Simulation

Simulates a MIL-STD-1553B Bus Controller - the device that controls
all communication on the 1553 bus.
"""

from typing import Optional, List, Dict, Callable
from dataclasses import dataclass
import time

from mil1553.devices.base import Device1553, DeviceType
from mil1553.core.message import Message, MessageType, create_bc_to_rt_message, create_rt_to_bc_message
from mil1553.core.word import CommandWord, StatusWord, DataWord
from mil1553.core.constants import ModeCode, BROADCAST_ADDRESS


@dataclass
class BCCommand:
    """
    Scheduled BC command.

    Attributes:
        rt_address: Target RT address
        subaddress: Target subaddress
        transmit: True for RT transmit, False for RT receive
        data_words: Data to send (for BC-to-RT)
        interval_us: Repeat interval in microseconds (0 = one-shot)
        mode_code: Optional mode code for mode commands
    """
    rt_address: int
    subaddress: int
    transmit: bool = False
    data_words: List[DataWord] = None
    interval_us: float = 0
    mode_code: Optional[ModeCode] = None
    last_executed: float = 0


class BusController(Device1553):
    """
    Simulated Bus Controller (BC).

    The BC is the master device on a 1553 bus. It:
    - Initiates all data transfers (§4.3.4.1.1)
    - Polls RTs for data
    - Sends commands to RTs
    - Manages bus timing

    Example:
        >>> from mil1553.devices import BusController, RemoteTerminal, VirtualBus
        >>>
        >>> bus = VirtualBus()
        >>> bc = BusController(name="FlightComputer")
        >>> rt = RemoteTerminal(rt_address=5, name="NavSensor")
        >>>
        >>> bus.connect(bc)
        >>> bus.connect(rt)
        >>>
        >>> # Send command to RT
        >>> bc.send_to_rt(
        ...     rt_address=5,
        ...     subaddress=10,
        ...     data=[DataWord(payload=0x1234)]
        ... )
        >>>
        >>> # Poll RT for data
        >>> response = bc.receive_from_rt(
        ...     rt_address=5,
        ...     subaddress=12,
        ...     word_count=3
        ... )
    """

    def __init__(self, name: Optional[str] = None):
        """
        Initialize Bus Controller.

        Args:
            name: Optional BC name for identification
        """
        super().__init__(DeviceType.BUS_CONTROLLER, name)
        self.command_schedule: List[BCCommand] = []
        self.rt_table: Dict[int, Dict] = {}  # RT address -> info

    def process_message(self, message: Message) -> Optional[Message]:
        """
        Process incoming message.

        Note: BC typically doesn't process incoming messages -
        it initiates transfers and receives responses.
        """
        self.log_message(message, "rx")
        self.statistics.messages_received += 1
        return None

    def send_to_rt(
        self,
        rt_address: int,
        subaddress: int,
        data: List[DataWord],
        timeout_us: float = 100
    ) -> Optional[StatusWord]:
        """
        Send data to an RT (BC-to-RT transfer).

        Standard Reference: §4.3.4.2.1 - BC to RT Transfer

        Args:
            rt_address: Target RT address (1-30)
            subaddress: Target subaddress (0-31)
            data: Data words to send
            timeout_us: Response timeout in microseconds

        Returns:
            RT's status word (if received), None on timeout

        Example:
            >>> status = bc.send_to_rt(
            ...     rt_address=5,
            ...     subaddress=10,
            ...     data=[DataWord(payload=0x1234), DataWord(payload=0x5678)]
            ... )
            >>> if status and not status.message_error:
            ...     print("RT acknowledged successfully")
        """
        if not self.bus:
            raise RuntimeError("BC not connected to bus")

        # Create BC-to-RT message
        message = create_bc_to_rt_message(
            rt_address=rt_address,
            subaddress=subaddress,
            data_words=data
        )

        self.log_message(message, "tx")
        self.statistics.messages_sent += 1

        # Transmit and wait for status response
        response = self.bus.transmit(message, source=self, wait_for_response=True)

        if response and response.status_words:
            return response.status_words[0]
        return None

    def receive_from_rt(
        self,
        rt_address: int,
        subaddress: int,
        word_count: int,
        timeout_us: float = 100
    ) -> Optional[Message]:
        """
        Receive data from an RT (RT-to-BC transfer).

        Standard Reference: §4.3.4.2.2 - RT to BC Transfer

        Args:
            rt_address: Source RT address
            subaddress: Source subaddress
            word_count: Number of data words to request
            timeout_us: Response timeout in microseconds

        Returns:
            RT's response message (status + data), None on timeout

        Example:
            >>> response = bc.receive_from_rt(
            ...     rt_address=5,
            ...     subaddress=12,
            ...     word_count=3
            ... )
            >>> if response:
            ...     for data_word in response.data_words:
            ...         print(f"Data: 0x{data_word.payload:04X}")
        """
        if not self.bus:
            raise RuntimeError("BC not connected to bus")

        # Create command requesting RT to transmit (T/R = 1)
        cmd = CommandWord(
            rt_address=rt_address,
            transmit_receive=1,  # RT transmits to BC
            subaddress=subaddress,
            word_count=word_count
        )

        # BC sends command - response will be RT-to-BC
        message = Message(
            message_type=MessageType.BC_TO_RT,  # Command from BC
            command_word=cmd
        )

        self.log_message(message, "tx")
        self.statistics.messages_sent += 1

        # Transmit and wait for response
        response = self.bus.transmit(message, source=self, wait_for_response=True)

        if response:
            self.log_message(response, "rx")
            self.statistics.messages_received += 1

        return response

    def send_mode_command(
        self,
        rt_address: int,
        mode_code: ModeCode,
        data_word: Optional[DataWord] = None,
        timeout_us: float = 100
    ) -> Optional[StatusWord]:
        """
        Send mode command to RT.

        Standard Reference: §4.3.4.3 - Mode Command

        Args:
            rt_address: Target RT address (or 31 for broadcast)
            mode_code: Mode command code
            data_word: Optional data word for transmit mode commands
            timeout_us: Response timeout

        Returns:
            RT's status word (if not broadcast)

        Example:
            >>> # Synchronize RT
            >>> status = bc.send_mode_command(
            ...     rt_address=5,
            ...     mode_code=ModeCode.SYNCHRONIZE
            ... )
        """
        if not self.bus:
            raise RuntimeError("BC not connected to bus")

        # Create mode command
        cmd = CommandWord(
            rt_address=rt_address,
            transmit_receive=1 if data_word else 0,
            subaddress=0,  # Mode command indicator
            word_count=mode_code.value
        )

        # BC sends mode command
        message = Message(
            message_type=MessageType.BC_TO_RT,  # Command from BC
            command_word=cmd,
            data_words=[data_word] if data_word else []
        )

        self.log_message(message, "tx")
        self.statistics.messages_sent += 1

        # Broadcast mode commands don't get responses
        if rt_address == BROADCAST_ADDRESS:
            self.bus.transmit(message, source=self, wait_for_response=False)
            return None

        response = self.bus.transmit(message, source=self, wait_for_response=True)

        if response and response.status_words:
            return response.status_words[0]
        return None

    def broadcast(
        self,
        subaddress: int,
        data: List[DataWord]
    ):
        """
        Broadcast data to all RTs.

        Standard Reference: §4.3.4.4 - Broadcast Command

        Args:
            subaddress: Broadcast subaddress
            data: Data to broadcast

        Note:
            Broadcast messages do not receive status responses.

        Example:
            >>> # Send time sync to all RTs
            >>> bc.broadcast(
            ...     subaddress=30,  # Time sync subaddress
            ...     data=[DataWord(payload=current_time)]
            ... )
        """
        if not self.bus:
            raise RuntimeError("BC not connected to bus")

        message = create_bc_to_rt_message(
            rt_address=BROADCAST_ADDRESS,
            subaddress=subaddress,
            data_words=data
        )

        message.message_type = MessageType.BROADCAST

        self.log_message(message, "tx")
        self.statistics.messages_sent += 1

        # Broadcast doesn't wait for response
        self.bus.transmit(message, source=self, wait_for_response=False)

    def add_to_schedule(
        self,
        rt_address: int,
        subaddress: int,
        transmit: bool = False,
        data_words: Optional[List[DataWord]] = None,
        interval_us: float = 1000
    ):
        """
        Add a periodic command to the schedule.

        Args:
            rt_address: Target RT
            subaddress: Target subaddress
            transmit: True for RT-to-BC, False for BC-to-RT
            data_words: Data for BC-to-RT transfers
            interval_us: Execution interval in microseconds

        Example:
            >>> # Poll sensor every 10ms
            >>> bc.add_to_schedule(
            ...     rt_address=5,
            ...     subaddress=12,
            ...     transmit=True,  # RT transmits data
            ...     interval_us=10000
            ... )
        """
        command = BCCommand(
            rt_address=rt_address,
            subaddress=subaddress,
            transmit=transmit,
            data_words=data_words or [],
            interval_us=interval_us
        )

        self.command_schedule.append(command)

    def execute_schedule(self, duration_s: float = 1.0):
        """
        Execute scheduled commands for a duration.

        Args:
            duration_s: How long to run schedule (seconds)

        Example:
            >>> bc.add_to_schedule(rt_address=5, subaddress=10, interval_us=1000)
            >>> bc.add_to_schedule(rt_address=6, subaddress=11, interval_us=2000)
            >>> bc.execute_schedule(duration_s=5.0)  # Run for 5 seconds
        """
        if not self.bus:
            raise RuntimeError("BC not connected to bus")

        start_time = time.time()
        current_time = start_time

        while (current_time - start_time) < duration_s:
            current_time_us = current_time * 1e6

            for cmd in self.command_schedule:
                # Check if it's time to execute this command
                if current_time_us - cmd.last_executed >= cmd.interval_us:
                    if cmd.transmit:
                        # RT-to-BC
                        self.receive_from_rt(
                            rt_address=cmd.rt_address,
                            subaddress=cmd.subaddress,
                            word_count=len(cmd.data_words) if cmd.data_words else 1
                        )
                    else:
                        # BC-to-RT
                        self.send_to_rt(
                            rt_address=cmd.rt_address,
                            subaddress=cmd.subaddress,
                            data=cmd.data_words
                        )

                    cmd.last_executed = current_time_us

            time.sleep(0.0001)  # Small sleep to prevent busy-waiting
            current_time = time.time()
