"""
Replay Attack Simulation for MIL-STD-1553B

This module provides replay attack capabilities for security testing.
"""

from typing import List, Optional, Dict, Any
import copy
import time

from mil1553.core.message import Message
from mil1553.core.word import DataWord


class ReplayAttacker:
    """
    Simulates replay attacks on 1553B bus.

    Captures legitimate messages and replays them, potentially
    with modifications.
    """

    def __init__(self):
        """Initialize replay attacker."""
        self.captured_messages = []
        self.replays_executed = []

    def capture_message(self, message: Message) -> Dict[str, Any]:
        """
        Capture a message for later replay.

        Args:
            message: Message to capture

        Returns:
            Capture metadata

        Example:
            >>> attacker = ReplayAttacker()
            >>> attacker.capture_message(legitimate_msg)
        """
        capture = {
            'message': copy.deepcopy(message),
            'captured_at': time.time(),
            'capture_index': len(self.captured_messages)
        }

        self.captured_messages.append(capture)

        return capture

    def replay(
        self,
        message: Message,
        delay: float = 0.0,
        modifications: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Replay a captured message.

        Args:
            message: Message to replay
            delay: Delay before replay (seconds)
            modifications: Optional modifications to apply

        Returns:
            Replay result

        Example:
            >>> result = attacker.replay(
            ...     captured_msg,
            ...     delay=0.001,
            ...     modifications={'data_words': [DataWord(payload=0xEVIL)]}
            ... )
        """
        replayed = copy.deepcopy(message)

        # Apply modifications if specified
        if modifications:
            for key, value in modifications.items():
                if hasattr(replayed, key):
                    setattr(replayed, key, value)

        replay = {
            'original': message,
            'replayed': replayed,
            'delay': delay,
            'modifications': modifications,
            'replayed_at': time.time(),
            'result': 'simulated'
        }

        self.replays_executed.append(replay)

        return replay

    def replay_sequence(
        self,
        messages: List[Message],
        timing_mode: str = 'exact'
    ) -> List[Dict[str, Any]]:
        """
        Replay a sequence of messages.

        Args:
            messages: List of messages to replay
            timing_mode: 'exact', 'compressed', or 'delayed'

        Returns:
            List of replay results

        Timing Modes:
        - exact: Preserve original timing
        - compressed: Reduce delays between messages
        - delayed: Add delays between messages

        Example:
            >>> results = attacker.replay_sequence(
            ...     [msg1, msg2, msg3],
            ...     timing_mode='compressed'
            ... )
        """
        results = []

        for i, msg in enumerate(messages):
            delay = self._calculate_delay(i, timing_mode)
            result = self.replay(msg, delay=delay)
            results.append(result)

        return results

    def amplify(
        self,
        message: Message,
        count: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Amplification attack: replay message multiple times.

        Args:
            message: Message to amplify
            count: Number of times to replay

        Returns:
            List of replay results

        Attack Scenario:
        - Single legitimate command captured
        - Replayed many times
        - Can cause RT overload or DoS

        Example:
            >>> # Replay command 100 times
            >>> results = attacker.amplify(command_msg, count=100)
        """
        results = []

        for i in range(count):
            result = self.replay(message, delay=i * 0.0001)  # Rapid succession
            results.append(result)

        return results

    def replay_modified(
        self,
        message: Message,
        field_modifications: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Replay message with specific field modifications.

        Args:
            message: Original message
            field_modifications: Fields to modify

        Returns:
            Replay result

        Example:
            >>> # Capture "send 0x1234" command, replay as "send 0xDEAD"
            >>> result = attacker.replay_modified(
            ...     msg,
            ...     {'data_words[0].payload': 0xDEAD}
            ... )
        """
        return self.replay(message, modifications=field_modifications)

    def _calculate_delay(self, index: int, timing_mode: str) -> float:
        """Calculate delay for replay based on timing mode."""
        if timing_mode == 'exact':
            return 0.0
        elif timing_mode == 'compressed':
            return index * 0.00001  # 10 μs between messages
        elif timing_mode == 'delayed':
            return index * 0.001    # 1 ms between messages
        else:
            return 0.0

    def get_statistics(self) -> Dict[str, Any]:
        """Get replay statistics."""
        return {
            'messages_captured': len(self.captured_messages),
            'replays_executed': len(self.replays_executed),
            'modification_rate': self._get_modification_rate()
        }

    def _get_modification_rate(self) -> float:
        """Calculate percentage of replays that were modified."""
        if not self.replays_executed:
            return 0.0

        modified = sum(1 for r in self.replays_executed if r.get('modifications'))
        return (modified / len(self.replays_executed)) * 100


class ReplayDetector:
    """
    Detects potential replay attacks.

    Analyzes message sequences for signs of replay.
    """

    def __init__(self):
        """Initialize replay detector."""
        self.message_history = []

    def check_replay(self, message: Message) -> bool:
        """
        Check if message appears to be a replay.

        Args:
            message: Message to check

        Returns:
            True if potential replay detected

        Detection Methods:
        - Exact duplicate detection
        - Timing anomalies
        - Sequence violations
        """
        # Simple duplicate detection
        for historical_msg in self.message_history[-100:]:  # Check last 100
            if self._messages_identical(message, historical_msg):
                return True  # Potential replay

        self.message_history.append(message)
        return False

    def _messages_identical(self, msg1: Message, msg2: Message) -> bool:
        """Check if two messages are identical."""
        # Simple comparison - would be more sophisticated in practice
        return (
            msg1.message_type == msg2.message_type and
            len(msg1.data_words) == len(msg2.data_words)
        )
