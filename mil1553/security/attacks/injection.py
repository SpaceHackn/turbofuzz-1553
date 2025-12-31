"""
Command Injection Attacks for MIL-STD-1553B

This module provides command injection capabilities for security testing,
allowing simulation of unauthorized command transmission.
"""

from typing import Optional, Dict, Any
from enum import Enum

from mil1553.core.word import CommandWord
from mil1553.core.message import Message, create_bc_to_rt_message
from mil1553.core.constants import MessageType


class InjectionTiming(Enum):
    """Timing options for injection attacks."""
    IMMEDIATE = "immediate"
    BETWEEN_MESSAGES = "between_messages"
    DURING_RESPONSE = "during_response"
    COLLISION = "collision"  # Intentional bus collision


class CommandInjector:
    """
    Simulates command injection attacks.

    In a real 1553B bus, only the BC should transmit commands.
    This class simulates scenarios where an RT or other device
    attempts to inject unauthorized commands.
    """

    def __init__(self):
        """Initialize command injector."""
        self.injections_attempted = []

    def inject_command(
        self,
        command: CommandWord,
        timing: InjectionTiming = InjectionTiming.BETWEEN_MESSAGES,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Inject an unauthorized command onto the bus.

        Args:
            command: Command word to inject
            timing: When to inject the command
            metadata: Optional metadata about the injection

        Returns:
            Dictionary with injection results

        Standard Violation: §4.3.4.1.1
        "The BC shall initiate all data transfers on the bus."

        Example:
            >>> injector = CommandInjector()
            >>> malicious_cmd = CommandWord(rt_address=7, transmit_receive=1, ...)
            >>> result = injector.inject_command(malicious_cmd)
        """
        injection = {
            'command': command,
            'timing': timing,
            'timestamp': None,  # Would be set by actual transmission
            'metadata': metadata or {},
            'result': 'simulated'  # In real implementation, actual result
        }

        self.injections_attempted.append(injection)

        return injection

    def inject_between_messages(
        self,
        msg1: Message,
        msg2: Message,
        injected: Message,
        gap_time: float = 2.0
    ) -> Dict[str, Any]:
        """
        Inject a message between two legitimate messages.

        Violates inter-message gap timing if gap_time < 4.0 μs.

        Args:
            msg1: First legitimate message
            msg2: Second legitimate message
            injected: Message to inject
            gap_time: Gap time to use (μs)

        Returns:
            Injection result

        Standard Violations:
        - §4.3.4.1.1: Only BC transmits commands
        - §4.3.4.6.2.3.1: Inter-message gap ≥ 4 μs

        Example:
            >>> result = injector.inject_between_messages(
            ...     msg1, msg2, malicious_msg, gap_time=2.0
            ... )
        """
        injection = {
            'type': 'between_messages',
            'msg1': msg1,
            'msg2': msg2,
            'injected': injected,
            'gap_time': gap_time,
            'gap_violation': gap_time < 4.0,
            'result': 'simulated'
        }

        self.injections_attempted.append(injection)

        return injection

    def spoof_rt_address(
        self,
        original_address: int,
        spoofed_address: int
    ) -> CommandWord:
        """
        Create command with spoofed RT address.

        Args:
            original_address: Original RT address
            spoofed_address: Spoofed RT address

        Returns:
            Command with spoofed address

        Attack Scenario:
        - RT X sends command claiming to be from RT Y
        - Tests address validation

        Example:
            >>> # RT 7 pretends to be RT 5
            >>> cmd = injector.spoof_rt_address(original_address=7, spoofed_address=5)
        """
        return CommandWord(
            rt_address=spoofed_address,
            transmit_receive=1,
            subaddress=10,
            word_count=1
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get injection statistics."""
        return {
            'total_injections': len(self.injections_attempted),
            'timing_distribution': self._get_timing_distribution()
        }

    def _get_timing_distribution(self) -> Dict[str, int]:
        """Get distribution of injection timings."""
        distribution = {}
        for inj in self.injections_attempted:
            timing = inj.get('timing', 'unknown')
            if isinstance(timing, InjectionTiming):
                timing = timing.value
            distribution[str(timing)] = distribution.get(str(timing), 0) + 1
        return distribution
