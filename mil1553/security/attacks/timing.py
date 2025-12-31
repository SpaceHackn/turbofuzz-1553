"""
Timing Attacks for MIL-STD-1553B Security Testing

This module provides timing-based attack simulation for testing
implementation resilience to timing violations.
"""

from typing import List, Optional, Dict, Any

from mil1553.core.message import Message
from mil1553.core.constants import TimingConstants


class TimingAttacker:
    """
    Simulates timing-based attacks on 1553B bus.

    Tests implementation response to timing violations.
    """

    def __init__(self):
        """Initialize timing attacker."""
        self.attacks_executed = []

    def violate_response_time(
        self,
        message: Message,
        violation_us: float
    ) -> Message:
        """
        Create message with RT response time violation.

        Args:
            message: Original message
            violation_us: Violation amount in microseconds
                         Negative = too early
                         Positive = too late

        Returns:
            Message with modified response timing

        Standard Violation: §4.3.4.6.2.3.2
        "RT shall respond in not less than 4 μs and not more than 12 μs"

        Example:
            >>> attacker = TimingAttacker()
            >>> # RT responds 2 μs too early (< 4 μs minimum)
            >>> early = attacker.violate_response_time(msg, violation_us=-2.0)
            >>> # RT responds 5 μs too late (> 12 μs maximum)
            >>> late = attacker.violate_response_time(msg, violation_us=+5.0)
        """
        import copy
        violated = copy.deepcopy(message)

        # Calculate violated response time
        normal_response = TimingConstants.RESPONSE_TIME_TYPICAL
        violated_response = normal_response + violation_us

        # Store in metadata
        violated.set_metadata('response_time', violated_response)
        violated.set_metadata('response_violation', violation_us)

        attack = {
            'type': 'response_time_violation',
            'message': violated,
            'violation_us': violation_us,
            'actual_time': violated_response,
            'min_allowed': TimingConstants.RESPONSE_TIME_MIN,
            'max_allowed': TimingConstants.RESPONSE_TIME_MAX,
            'is_violation': (
                violated_response < TimingConstants.RESPONSE_TIME_MIN or
                violated_response > TimingConstants.RESPONSE_TIME_MAX
            )
        }

        self.attacks_executed.append(attack)

        return violated

    def create_bus_flood(
        self,
        duration: float,
        message_template: Message,
        gap_time: float = 0.5
    ) -> Dict[str, Any]:
        """
        Create bus flooding attack.

        Sends messages in rapid succession, violating inter-message gap.

        Args:
            duration: Flood duration in microseconds
            message_template: Template message to flood with
            gap_time: Inter-message gap (< 4 μs violates standard)

        Returns:
            Flood attack metadata

        Standard Violation: §4.3.4.6.2.3.1
        "Inter-message gap shall be not less than 4 μs"

        Impact:
        - Bus saturation
        - Legitimate traffic blocked
        - RT overload/DoS

        Example:
            >>> # Flood bus for 1ms with 0.5 μs gaps (< 4 μs minimum)
            >>> flood = attacker.create_bus_flood(
            ...     duration=1000,
            ...     message_template=msg,
            ...     gap_time=0.5
            ... )
        """
        message_time = message_template.calculate_message_duration()
        messages_per_window = int(duration / (message_time + gap_time))

        flood = {
            'type': 'bus_flood',
            'duration_us': duration,
            'gap_time_us': gap_time,
            'message_template': message_template,
            'estimated_messages': messages_per_window,
            'gap_violation': gap_time < TimingConstants.INTER_MESSAGE_GAP_MIN,
            'saturation_percent': self._calculate_saturation(message_time, gap_time)
        }

        self.attacks_executed.append(flood)

        return flood

    def manipulate_gaps(
        self,
        messages: List[Message],
        gap_factor: float = 0.1
    ) -> List[Message]:
        """
        Manipulate inter-message gaps in a sequence.

        Args:
            messages: List of messages
            gap_factor: Multiplier for gaps (< 1.0 = compressed, > 1.0 = expanded)

        Returns:
            Messages with modified gaps

        Example:
            >>> # Compress gaps to 10% of normal
            >>> compressed = attacker.manipulate_gaps(messages, gap_factor=0.1)
        """
        import copy
        manipulated = []

        base_gap = TimingConstants.INTER_MESSAGE_GAP_TYPICAL
        new_gap = base_gap * gap_factor

        for msg in messages:
            modified = copy.deepcopy(msg)
            modified.gap_time = new_gap
            manipulated.append(modified)

        attack = {
            'type': 'gap_manipulation',
            'gap_factor': gap_factor,
            'original_gap': base_gap,
            'new_gap': new_gap,
            'message_count': len(messages),
            'violation': new_gap < TimingConstants.INTER_MESSAGE_GAP_MIN
        }

        self.attacks_executed.append(attack)

        return manipulated

    def create_timeout_exploit(
        self,
        message: Message,
        timeout_us: float = 1000
    ) -> Dict[str, Any]:
        """
        Create timeout exploitation attack.

        Forces RT or BC into timeout condition.

        Args:
            message: Message to delay
            timeout_us: Timeout to force (microseconds)

        Returns:
            Timeout attack metadata

        Attack Scenario:
        - BC sends command
        - RT intentionally delays response beyond timeout
        - BC must handle timeout gracefully

        Example:
            >>> timeout = attacker.create_timeout_exploit(msg, timeout_us=100)
        """
        exploit = {
            'type': 'timeout_exploit',
            'message': message,
            'timeout_us': timeout_us,
            'expected_response': TimingConstants.RESPONSE_TIME_MAX,
            'timeout_factor': timeout_us / TimingConstants.RESPONSE_TIME_MAX
        }

        self.attacks_executed.append(exploit)

        return exploit

    def create_timing_race(
        self,
        msg1: Message,
        msg2: Message,
        gap_us: float = 1.0
    ) -> Dict[str, Any]:
        """
        Create timing race condition.

        Sends two messages with minimal gap to test race handling.

        Args:
            msg1: First message
            msg2: Second message
            gap_us: Gap between messages (μs)

        Returns:
            Race condition metadata

        Attack Scenario:
        - Two commands sent nearly simultaneously
        - Tests BC/RT ability to serialize
        - Can expose race conditions

        Example:
            >>> race = attacker.create_timing_race(cmd1, cmd2, gap_us=0.5)
        """
        race = {
            'type': 'timing_race',
            'msg1': msg1,
            'msg2': msg2,
            'gap_us': gap_us,
            'gap_violation': gap_us < TimingConstants.INTER_MESSAGE_GAP_MIN,
            'potential_collision': gap_us < 2.0
        }

        self.attacks_executed.append(race)

        return race

    def _calculate_saturation(self, message_time: float, gap_time: float) -> float:
        """
        Calculate bus saturation percentage.

        Args:
            message_time: Time per message (μs)
            gap_time: Inter-message gap (μs)

        Returns:
            Saturation percentage (0-100)
        """
        total_time = message_time + gap_time
        active_time = message_time
        return (active_time / total_time) * 100

    def get_statistics(self) -> Dict[str, Any]:
        """Get timing attack statistics."""
        return {
            'attacks_executed': len(self.attacks_executed),
            'attack_types': self._get_attack_distribution(),
            'violation_rate': self._get_violation_rate()
        }

    def _get_attack_distribution(self) -> Dict[str, int]:
        """Get distribution of attack types."""
        distribution = {}
        for attack in self.attacks_executed:
            attack_type = attack.get('type', 'unknown')
            distribution[attack_type] = distribution.get(attack_type, 0) + 1
        return distribution

    def _get_violation_rate(self) -> float:
        """Calculate percentage of attacks that violate standards."""
        if not self.attacks_executed:
            return 0.0

        violations = sum(
            1 for a in self.attacks_executed
            if a.get('is_violation') or a.get('gap_violation') or a.get('violation')
        )

        return (violations / len(self.attacks_executed)) * 100


class TimingMonitor:
    """
    Monitors and detects timing anomalies.

    Can be used to detect timing attacks.
    """

    def __init__(self):
        """Initialize timing monitor."""
        self.measurements = []

    def measure_response_time(self, message: Message) -> Dict[str, Any]:
        """
        Measure RT response time.

        Args:
            message: Message to measure

        Returns:
            Timing measurement
        """
        response_time = message.get_response_time()

        measurement = {
            'message': message,
            'response_time_us': response_time,
            'within_spec': (
                TimingConstants.RESPONSE_TIME_MIN <= response_time <= TimingConstants.RESPONSE_TIME_MAX
            ) if response_time else None
        }

        self.measurements.append(measurement)

        return measurement

    def detect_timing_anomaly(self, message: Message) -> Optional[str]:
        """
        Detect timing anomalies in message.

        Args:
            message: Message to check

        Returns:
            Anomaly description or None

        Detection Types:
        - Response time violations
        - Gap time violations
        - Unusual timing patterns
        """
        response_time = message.get_response_time()

        if response_time:
            if response_time < TimingConstants.RESPONSE_TIME_MIN:
                return f"Response too early: {response_time} μs (min: {TimingConstants.RESPONSE_TIME_MIN} μs)"
            elif response_time > TimingConstants.RESPONSE_TIME_MAX:
                return f"Response too late: {response_time} μs (max: {TimingConstants.RESPONSE_TIME_MAX} μs)"

        if message.gap_time:
            if message.gap_time < TimingConstants.INTER_MESSAGE_GAP_MIN:
                return f"Insufficient gap: {message.gap_time} μs (min: {TimingConstants.INTER_MESSAGE_GAP_MIN} μs)"

        return None
