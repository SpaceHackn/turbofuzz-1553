"""
Attack Scenario Framework for MIL-STD-1553B Security Testing

This module provides a framework for defining, executing, and managing
reusable security test scenarios that combine multiple attack techniques.
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import copy

from mil1553.core.message import Message
from mil1553.core.word import CommandWord, StatusWord, DataWord
from mil1553.security.fuzzer import Fuzzer, BitFlipFuzzer, BoundaryFuzzer, SemanticFuzzer
from mil1553.security.attacks.malformed import MalformedPacketGenerator
from mil1553.security.attacks.injection import CommandInjector, InjectionTiming
from mil1553.security.attacks.replay import ReplayAttacker
from mil1553.security.attacks.timing import TimingAttacker
from mil1553.security.validators.security import SecurityValidator


class ScenarioType(Enum):
    """Types of security test scenarios."""
    FUZZING = "fuzzing"
    MALFORMED = "malformed"
    INJECTION = "injection"
    REPLAY = "replay"
    TIMING = "timing"
    COMBINED = "combined"


class AttackComplexity(Enum):
    """Complexity level of attack scenario."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScenarioResult:
    """
    Result of executing a test scenario.

    Attributes:
        scenario_name: Name of the scenario
        success: Whether execution succeeded
        messages_generated: Number of test messages generated
        anomalies_detected: Anomalies found during validation
        attack_statistics: Statistics from attack modules
        errors: Any errors encountered
    """
    scenario_name: str
    success: bool
    messages_generated: int
    anomalies_detected: List[Any]
    attack_statistics: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        status = "✓ SUCCESS" if self.success else "✗ FAILED"
        return f"[{status}] {self.scenario_name}: {self.messages_generated} messages, {len(self.anomalies_detected)} anomalies"


@dataclass
class TestScenario:
    """
    Defines a reusable security test scenario.

    A scenario combines attack techniques, target messages, and validation
    criteria into a reproducible test case.

    Attributes:
        name: Scenario name
        description: What the scenario tests
        scenario_type: Type of attack
        complexity: Attack complexity level
        template_message: Base message for attack generation
        attack_config: Configuration for attack modules
        validation_enabled: Whether to validate generated messages
        max_iterations: Maximum test iterations

    Example:
        >>> scenario = TestScenario(
        ...     name="Basic Fuzzing",
        ...     description="Bit-flip fuzzing of BC-to-RT commands",
        ...     scenario_type=ScenarioType.FUZZING,
        ...     template_message=msg,
        ...     attack_config={'strategy': 'bitflip', 'mutation_rate': 0.1}
        ... )
        >>> result = scenario.execute()
    """
    name: str
    description: str
    scenario_type: ScenarioType
    complexity: AttackComplexity
    template_message: Optional[Message] = None
    attack_config: Dict[str, Any] = field(default_factory=dict)
    validation_enabled: bool = True
    max_iterations: int = 100

    def execute(self) -> ScenarioResult:
        """
        Execute the scenario.

        Returns:
            ScenarioResult with execution details
        """
        errors = []
        messages = []
        anomalies = []
        stats = {}

        try:
            if self.scenario_type == ScenarioType.FUZZING:
                messages, stats = self._execute_fuzzing()
            elif self.scenario_type == ScenarioType.MALFORMED:
                messages, stats = self._execute_malformed()
            elif self.scenario_type == ScenarioType.INJECTION:
                messages, stats = self._execute_injection()
            elif self.scenario_type == ScenarioType.REPLAY:
                messages, stats = self._execute_replay()
            elif self.scenario_type == ScenarioType.TIMING:
                messages, stats = self._execute_timing()
            elif self.scenario_type == ScenarioType.COMBINED:
                messages, stats = self._execute_combined()

            # Validate if enabled
            if self.validation_enabled and messages:
                validator = SecurityValidator()
                for msg in messages:
                    anomalies.extend(validator.check_anomalies(msg))
                stats['validation'] = validator.get_statistics()

            success = True

        except Exception as e:
            errors.append(str(e))
            success = False

        return ScenarioResult(
            scenario_name=self.name,
            success=success,
            messages_generated=len(messages),
            anomalies_detected=anomalies,
            attack_statistics=stats,
            errors=errors
        )

    def _execute_fuzzing(self) -> tuple[List[Message], Dict[str, Any]]:
        """Execute fuzzing scenario."""
        if not self.template_message:
            raise ValueError("Fuzzing requires template_message")

        strategy = self.attack_config.get('strategy', 'bitflip')
        mutation_rate = self.attack_config.get('mutation_rate', 0.05)
        count = min(self.max_iterations, self.attack_config.get('count', 100))

        messages = []
        all_stats = {}

        if strategy == 'bitflip':
            fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=mutation_rate))
            messages = fuzzer.generate_test_cases(self.template_message, count=count)
            all_stats = fuzzer.get_statistics()
        elif strategy == 'boundary':
            fuzzer = Fuzzer(strategy=BoundaryFuzzer())
            messages = fuzzer.generate_test_cases(self.template_message, count=count)
            all_stats = fuzzer.get_statistics()
        elif strategy == 'semantic':
            fuzzer = Fuzzer(strategy=SemanticFuzzer())
            messages = fuzzer.generate_test_cases(self.template_message, count=count)
            all_stats = fuzzer.get_statistics()
        elif strategy == 'all':
            # Run all strategies and combine results
            count_per_strategy = count // 3

            fuzzer1 = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=mutation_rate))
            messages.extend(fuzzer1.generate_test_cases(self.template_message, count=count_per_strategy))

            fuzzer2 = Fuzzer(strategy=BoundaryFuzzer())
            messages.extend(fuzzer2.generate_test_cases(self.template_message, count=count_per_strategy))

            fuzzer3 = Fuzzer(strategy=SemanticFuzzer())
            messages.extend(fuzzer3.generate_test_cases(self.template_message, count=count_per_strategy))

            all_stats = {
                'total_generated': len(messages),
                'strategies_used': ['BitFlipFuzzer', 'BoundaryFuzzer', 'SemanticFuzzer']
            }

        return messages, all_stats

    def _execute_malformed(self) -> tuple[List[Message], Dict[str, Any]]:
        """Execute malformed packet scenario."""
        if not self.template_message:
            raise ValueError("Malformed packet generation requires template_message")

        gen = MalformedPacketGenerator()
        messages = []

        # Generate suite of malformed variants
        if self.attack_config.get('generate_suite', True):
            messages.extend(gen.generate_malformed_suite(self.template_message))

        # Specific malformations
        if 'parity_errors' in self.attack_config:
            for word in self.template_message.command_words:
                messages.append(
                    copy.deepcopy(self.template_message)
                )
                messages[-1].command_words[0] = gen.generate_parity_error(word)

        if 'word_count_mismatch' in self.attack_config:
            for count in self.attack_config['word_count_mismatch']:
                messages.append(
                    gen.generate_word_count_mismatch(self.template_message, count)
                )

        stats = {
            'malformed_types': len(set(type(m) for m in messages)),
            'total_generated': len(messages)
        }

        return messages, stats

    def _execute_injection(self) -> tuple[List[Message], Dict[str, Any]]:
        """Execute command injection scenario."""
        injector = CommandInjector()
        messages = []

        timing = self.attack_config.get('timing', InjectionTiming.BETWEEN_MESSAGES)
        if isinstance(timing, str):
            timing = InjectionTiming(timing)

        # Generate injection commands
        count = min(self.max_iterations, self.attack_config.get('count', 10))

        for i in range(count):
            cmd = CommandWord(
                rt_address=self.attack_config.get('rt_address', 5),
                transmit_receive=self.attack_config.get('transmit_receive', 0),
                subaddress=self.attack_config.get('subaddress', 10),
                word_count=self.attack_config.get('word_count', 1)
            )

            result = injector.inject_command(cmd, timing=timing)
            # Note: injection returns dict, not Message
            # In real implementation, would create Message from injection

        stats = injector.get_statistics()

        return messages, stats

    def _execute_replay(self) -> tuple[List[Message], Dict[str, Any]]:
        """Execute replay attack scenario."""
        if not self.template_message:
            raise ValueError("Replay requires template_message")

        attacker = ReplayAttacker()
        messages = []

        # Capture template
        attacker.capture_message(self.template_message)

        # Replay scenarios
        replay_count = self.attack_config.get('replay_count', 10)

        if self.attack_config.get('amplify', False):
            results = attacker.amplify(self.template_message, count=replay_count)
            messages.extend([r['replayed'] for r in results])
        else:
            for i in range(replay_count):
                delay = self.attack_config.get('delay', 0.001) * i
                result = attacker.replay(self.template_message, delay=delay)
                messages.append(result['replayed'])

        stats = attacker.get_statistics()

        return messages, stats

    def _execute_timing(self) -> tuple[List[Message], Dict[str, Any]]:
        """Execute timing attack scenario."""
        if not self.template_message:
            raise ValueError("Timing attack requires template_message")

        attacker = TimingAttacker()
        messages = []

        # Response time violations
        if 'response_violations' in self.attack_config:
            for violation in self.attack_config['response_violations']:
                violated = attacker.violate_response_time(
                    self.template_message,
                    violation_us=violation
                )
                messages.append(violated)

        # Gap manipulation
        if 'gap_manipulation' in self.attack_config:
            gap_factor = self.attack_config['gap_manipulation']
            manipulated = attacker.manipulate_gaps(
                [self.template_message],
                gap_factor=gap_factor
            )
            messages.extend(manipulated)

        stats = attacker.get_statistics()

        return messages, stats

    def _execute_combined(self) -> tuple[List[Message], Dict[str, Any]]:
        """Execute combined attack scenario."""
        if not self.template_message:
            raise ValueError("Combined attack requires template_message")

        messages = []
        combined_stats = {}

        # Execute multiple attack types in sequence
        for attack_type in self.attack_config.get('attack_sequence', []):
            temp_scenario = TestScenario(
                name=f"{self.name}_{attack_type}",
                description=f"Sub-scenario: {attack_type}",
                scenario_type=ScenarioType(attack_type),
                complexity=self.complexity,
                template_message=self.template_message,
                attack_config=self.attack_config.get(attack_type, {}),
                validation_enabled=False,
                max_iterations=self.max_iterations // len(self.attack_config.get('attack_sequence', [1]))
            )

            result = temp_scenario.execute()
            combined_stats[attack_type] = result.attack_statistics

        return messages, combined_stats

    def to_dict(self) -> Dict[str, Any]:
        """Export scenario to dictionary."""
        data = {
            'name': self.name,
            'description': self.description,
            'scenario_type': self.scenario_type.value,
            'complexity': self.complexity.value,
            'attack_config': self.attack_config,
            'validation_enabled': self.validation_enabled,
            'max_iterations': self.max_iterations
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any], template_message: Optional[Message] = None) -> 'TestScenario':
        """Import scenario from dictionary."""
        return cls(
            name=data['name'],
            description=data['description'],
            scenario_type=ScenarioType(data['scenario_type']),
            complexity=AttackComplexity(data['complexity']),
            template_message=template_message,
            attack_config=data.get('attack_config', {}),
            validation_enabled=data.get('validation_enabled', True),
            max_iterations=data.get('max_iterations', 100)
        )


class ScenarioLibrary:
    """
    Library of built-in security test scenarios.

    Provides pre-configured scenarios for common attack patterns.
    """

    @staticmethod
    def basic_fuzzing(template: Message) -> TestScenario:
        """
        Basic bit-flip fuzzing scenario.

        Standard Violations: Various (depends on mutations)

        Args:
            template: Template message for fuzzing

        Returns:
            Fuzzing scenario
        """
        return TestScenario(
            name="Basic Fuzzing",
            description="Bit-flip fuzzing with 5% mutation rate",
            scenario_type=ScenarioType.FUZZING,
            complexity=AttackComplexity.LOW,
            template_message=template,
            attack_config={
                'strategy': 'bitflip',
                'mutation_rate': 0.05,
                'count': 100
            }
        )

    @staticmethod
    def aggressive_fuzzing(template: Message) -> TestScenario:
        """
        Aggressive fuzzing with all strategies.

        Args:
            template: Template message for fuzzing

        Returns:
            Aggressive fuzzing scenario
        """
        return TestScenario(
            name="Aggressive Fuzzing",
            description="Multi-strategy fuzzing (bitflip, boundary, semantic)",
            scenario_type=ScenarioType.FUZZING,
            complexity=AttackComplexity.HIGH,
            template_message=template,
            attack_config={
                'strategy': 'all',
                'mutation_rate': 0.15,
                'count': 300
            }
        )

    @staticmethod
    def malformed_packet_suite(template: Message) -> TestScenario:
        """
        Comprehensive malformed packet testing.

        Standard Violations:
        - §4.3.5.2.1: Invalid sync, parity errors
        - §4.3.5.2.2.4: Word count mismatches
        - §4.3.5.2.3: Malformed status words

        Args:
            template: Template message

        Returns:
            Malformed packet scenario
        """
        return TestScenario(
            name="Malformed Packet Suite",
            description="Generate all malformed packet variants",
            scenario_type=ScenarioType.MALFORMED,
            complexity=AttackComplexity.MEDIUM,
            template_message=template,
            attack_config={
                'generate_suite': True,
                'parity_errors': True,
                'word_count_mismatch': [0, 1, 5, 10, 31]
            }
        )

    @staticmethod
    def command_injection_suite() -> TestScenario:
        """
        Command injection attack suite.

        Standard Violation: §4.3.4.1.1
        "Only BC shall initiate data transfers"

        Returns:
            Injection scenario
        """
        return TestScenario(
            name="Command Injection Suite",
            description="Unauthorized command injection from RT",
            scenario_type=ScenarioType.INJECTION,
            complexity=AttackComplexity.HIGH,
            attack_config={
                'timing': 'between_messages',
                'rt_address': 7,
                'transmit_receive': 1,
                'subaddress': 10,
                'word_count': 5,
                'count': 20
            }
        )

    @staticmethod
    def replay_attack_suite(template: Message) -> TestScenario:
        """
        Replay attack scenario.

        Tests replay detection and mitigation.

        Args:
            template: Message to replay

        Returns:
            Replay scenario
        """
        return TestScenario(
            name="Replay Attack Suite",
            description="Capture and replay with amplification",
            scenario_type=ScenarioType.REPLAY,
            complexity=AttackComplexity.MEDIUM,
            template_message=template,
            attack_config={
                'amplify': True,
                'replay_count': 50,
                'delay': 0.0001
            }
        )

    @staticmethod
    def timing_violation_suite(template: Message) -> TestScenario:
        """
        Timing violation scenario.

        Standard Violations:
        - §4.3.4.6.2.3.2: Response time (4-12 μs)
        - §4.3.4.6.2.3.1: Inter-message gap (≥ 4 μs)

        Args:
            template: Template message

        Returns:
            Timing scenario
        """
        return TestScenario(
            name="Timing Violation Suite",
            description="Response time and gap violations",
            scenario_type=ScenarioType.TIMING,
            complexity=AttackComplexity.MEDIUM,
            template_message=template,
            attack_config={
                'response_violations': [-2.0, -1.0, 5.0, 10.0],  # Too early/late
                'gap_manipulation': 0.1  # 10% of normal gap
            }
        )

    @staticmethod
    def bus_flood_attack(template: Message) -> TestScenario:
        """
        Bus flooding DoS attack.

        Standard Violation: §4.3.4.6.2.3.1
        Inter-message gap < 4 μs

        Args:
            template: Message to flood with

        Returns:
            Flood scenario
        """
        return TestScenario(
            name="Bus Flood Attack",
            description="DoS via bus saturation",
            scenario_type=ScenarioType.TIMING,
            complexity=AttackComplexity.CRITICAL,
            template_message=template,
            attack_config={
                'gap_manipulation': 0.05  # 5% of normal gap - severe violation
            }
        )

    @staticmethod
    def combined_attack(template: Message) -> TestScenario:
        """
        Combined multi-vector attack.

        Combines fuzzing, malformed packets, and timing attacks.

        Args:
            template: Template message

        Returns:
            Combined scenario
        """
        return TestScenario(
            name="Combined Multi-Vector Attack",
            description="Sequential fuzzing, malformed, and timing attacks",
            scenario_type=ScenarioType.COMBINED,
            complexity=AttackComplexity.CRITICAL,
            template_message=template,
            attack_config={
                'attack_sequence': ['fuzzing', 'malformed', 'timing'],
                'fuzzing': {'strategy': 'bitflip', 'mutation_rate': 0.1, 'count': 50},
                'malformed': {'generate_suite': True},
                'timing': {'gap_manipulation': 0.2}
            },
            max_iterations=150
        )

    @staticmethod
    def get_all_scenarios(template: Message) -> List[TestScenario]:
        """
        Get all built-in scenarios.

        Args:
            template: Template message for scenarios

        Returns:
            List of all scenarios
        """
        return [
            ScenarioLibrary.basic_fuzzing(template),
            ScenarioLibrary.aggressive_fuzzing(template),
            ScenarioLibrary.malformed_packet_suite(template),
            ScenarioLibrary.command_injection_suite(),
            ScenarioLibrary.replay_attack_suite(template),
            ScenarioLibrary.timing_violation_suite(template),
            ScenarioLibrary.bus_flood_attack(template),
            ScenarioLibrary.combined_attack(template)
        ]


class ScenarioRunner:
    """
    Orchestrates execution of multiple scenarios.

    Example:
        >>> runner = ScenarioRunner()
        >>> runner.add_scenario(ScenarioLibrary.basic_fuzzing(msg))
        >>> runner.add_scenario(ScenarioLibrary.malformed_packet_suite(msg))
        >>> results = runner.run_all()
        >>> runner.print_summary(results)
    """

    def __init__(self):
        """Initialize scenario runner."""
        self.scenarios: List[TestScenario] = []

    def add_scenario(self, scenario: TestScenario):
        """Add scenario to execution queue."""
        self.scenarios.append(scenario)

    def run_all(self) -> List[ScenarioResult]:
        """
        Execute all scenarios.

        Returns:
            List of results
        """
        results = []

        for scenario in self.scenarios:
            print(f"Executing: {scenario.name}...")
            result = scenario.execute()
            results.append(result)
            print(f"  {result}")

        return results

    def print_summary(self, results: List[ScenarioResult]):
        """Print execution summary."""
        print("\n" + "=" * 70)
        print("SCENARIO EXECUTION SUMMARY")
        print("=" * 70)

        total = len(results)
        successful = sum(1 for r in results if r.success)
        total_messages = sum(r.messages_generated for r in results)
        total_anomalies = sum(len(r.anomalies_detected) for r in results)

        print(f"Total Scenarios: {total}")
        print(f"Successful: {successful}/{total} ({successful/total*100:.1f}%)")
        print(f"Total Messages Generated: {total_messages}")
        print(f"Total Anomalies Detected: {total_anomalies}")

        print("\nPer-Scenario Results:")
        for result in results:
            status = "✓" if result.success else "✗"
            print(f"  {status} {result.scenario_name}: "
                  f"{result.messages_generated} msgs, "
                  f"{len(result.anomalies_detected)} anomalies")
            if result.errors:
                for error in result.errors:
                    print(f"    ERROR: {error}")

        print("=" * 70)

    def export_to_json(self, filename: str):
        """Export scenarios to JSON file."""
        data = {
            'scenarios': [s.to_dict() for s in self.scenarios]
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def import_from_json(cls, filename: str, template_message: Optional[Message] = None) -> 'ScenarioRunner':
        """Import scenarios from JSON file."""
        with open(filename, 'r') as f:
            data = json.load(f)

        runner = cls()
        for scenario_data in data['scenarios']:
            scenario = TestScenario.from_dict(scenario_data, template_message)
            runner.add_scenario(scenario)

        return runner
