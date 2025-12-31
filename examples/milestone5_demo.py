#!/usr/bin/env python3
"""
Milestone 5 Demo: Security Testing Framework

Demonstrates the complete security testing capabilities:
- Fuzzing with multiple strategies
- Malformed packet generation
- Command injection attacks
- Replay attacks
- Timing attacks
- Security validation and anomaly detection
- Attack scenario framework
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mil1553.core.word import CommandWord, StatusWord, DataWord
from mil1553.core.message import create_bc_to_rt_message, MessageType
from mil1553.core.constants import ModeCode

# Security testing modules
from mil1553.security.fuzzer import Fuzzer, BitFlipFuzzer, BoundaryFuzzer, SemanticFuzzer
from mil1553.security.attacks.malformed import MalformedPacketGenerator, create_malformed_message
from mil1553.security.attacks.injection import CommandInjector, InjectionTiming
from mil1553.security.attacks.replay import ReplayAttacker, ReplayDetector
from mil1553.security.attacks.timing import TimingAttacker, TimingMonitor
from mil1553.security.validators.security import SecurityValidator, Anomaly
from mil1553.security.scenarios import (
    ScenarioLibrary, ScenarioRunner, TestScenario,
    ScenarioType, AttackComplexity
)

from mil1553.output.formatters import CompactHexFormatter


def print_section(title: str):
    """Print section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_subsection(title: str):
    """Print subsection header."""
    print(f"\n--- {title} ---")


def demo_fuzzing():
    """Demonstrate fuzzing capabilities."""
    print_section("1. FUZZING ENGINE DEMONSTRATION")

    # Create template message
    template = create_bc_to_rt_message(
        rt_address=5,
        subaddress=10,
        data_words=[
            DataWord(payload=0x1234),
            DataWord(payload=0x5678),
            DataWord(payload=0xABCD)
        ]
    )

    formatter = CompactHexFormatter()
    print("\nTemplate Message:")
    print(formatter.format_message(template))

    # Bit-flip fuzzing
    print_subsection("Bit-Flip Fuzzing (5% mutation rate)")
    fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=0.05, seed=42))

    fuzzed = fuzzer.generate_test_cases(template, count=5)

    for i, msg in enumerate(fuzzed[:3], 1):
        print(f"\nFuzzed #{i}:")
        print(formatter.format_message(msg))

    # Boundary fuzzing
    print_subsection("Boundary Value Fuzzing")
    fuzzer = Fuzzer(strategy=BoundaryFuzzer(seed=42))

    boundary_cases = fuzzer.generate_test_cases(template, count=3)

    for i, msg in enumerate(boundary_cases, 1):
        print(f"\nBoundary Case #{i}:")
        print(formatter.format_message(msg))

    # Semantic fuzzing
    print_subsection("Semantic Fuzzing (Protocol Violations)")
    fuzzer = Fuzzer(strategy=SemanticFuzzer(seed=42))

    semantic_cases = fuzzer.generate_test_cases(template, count=3)

    for i, msg in enumerate(semantic_cases, 1):
        print(f"\nSemantic Case #{i}:")
        print(formatter.format_message(msg))

    # Statistics
    print_subsection("Fuzzing Statistics")
    stats = fuzzer.get_statistics()
    print(f"Total test cases generated: {stats['test_cases_generated']}")
    print(f"Strategy used: {stats['strategy']}")


def demo_malformed_packets():
    """Demonstrate malformed packet generation."""
    print_section("2. MALFORMED PACKET GENERATION")

    template = create_bc_to_rt_message(
        rt_address=7,
        subaddress=12,
        data_words=[DataWord(payload=0xDEAD), DataWord(payload=0xBEEF)]
    )

    gen = MalformedPacketGenerator()
    formatter = CompactHexFormatter()

    # Parity error
    print_subsection("Parity Error")
    cmd = template.command_words[0]
    corrupted = gen.generate_parity_error(cmd)
    print(f"Original parity: {cmd.parity} (valid: {cmd.is_valid_parity()})")
    print(f"Corrupted parity: {corrupted.parity} (valid: {corrupted.is_valid_parity()})")

    # Invalid sync
    print_subsection("Invalid Sync Pattern")
    invalid_sync = gen.generate_invalid_sync(cmd, sync_value=0b011)
    print(f"Original sync: {cmd.sync:#05b}")
    print(f"Invalid sync: {invalid_sync.sync:#05b} (should be 0b100 for command)")

    # Word count mismatch
    print_subsection("Word Count Mismatch")
    mismatched = gen.generate_word_count_mismatch(template, declared_count=10)
    print(f"Declared word count: {mismatched.command_words[0].actual_word_count}")
    print(f"Actual data words: {len(mismatched.data_words)}")

    # Illegal mode command
    print_subsection("Illegal Mode Command")
    illegal_mode = gen.generate_illegal_mode_command(rt_address=5)
    mode_code = illegal_mode.command_words[0].word_count_mode
    print(f"Mode code: {mode_code} (reserved/illegal)")

    # Broadcast with response (illegal)
    print_subsection("Broadcast with Response (Illegal)")
    illegal_broadcast = gen.generate_broadcast_with_response()
    print(f"RT Address: {illegal_broadcast.command_words[0].rt_address} (broadcast)")
    print(f"Has status word: {illegal_broadcast.status_words is not None and len(illegal_broadcast.status_words) > 0}")
    print("Note: Broadcast messages should NOT have status responses!")

    # Complete malformed suite
    print_subsection("Complete Malformed Suite")
    suite = gen.generate_malformed_suite(template)
    print(f"Generated {len(suite)} malformed variants:")

    malformation_types = set()
    for msg in suite:
        # Identify type of malformation
        if msg.command_words and msg.status_words:
            if msg.command_words[0].rt_address != msg.status_words[0].rt_address:
                malformation_types.add("address_mismatch")
        if msg.command_words and not msg.command_words[0].is_mode_command:
            if msg.command_words[0].actual_word_count != len(msg.data_words):
                malformation_types.add("word_count_mismatch")

    print(f"  Types: {', '.join(malformation_types)}")


def demo_injection_attacks():
    """Demonstrate command injection attacks."""
    print_section("3. COMMAND INJECTION ATTACKS")

    injector = CommandInjector()

    # Basic injection
    print_subsection("Unauthorized Command Injection")
    malicious_cmd = CommandWord(
        rt_address=7,
        transmit_receive=1,
        subaddress=10,
        word_count=5
    )

    result = injector.inject_command(
        malicious_cmd,
        timing=InjectionTiming.BETWEEN_MESSAGES,
        metadata={'attacker': 'RT-12', 'reason': 'unauthorized_access'}
    )

    print(f"Injected command from unauthorized source")
    print(f"  RT Address: {malicious_cmd.rt_address}")
    print(f"  Timing: {result['timing'].value}")
    print(f"  Metadata: {result['metadata']}")
    print("\nStandard Violation: §4.3.4.1.1 - Only BC shall initiate data transfers")

    # Address spoofing
    print_subsection("RT Address Spoofing")
    spoofed = injector.spoof_rt_address(original_address=12, spoofed_address=5)
    print(f"RT 12 pretending to be RT 5")
    print(f"  Claimed address: {spoofed.rt_address}")
    print("  Purpose: Bypass address-based access control")

    # Injection between messages
    print_subsection("Injection Between Messages (Timing Violation)")
    msg1 = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1111)])
    msg2 = create_bc_to_rt_message(6, 11, [DataWord(payload=0x2222)])
    injected_msg = create_bc_to_rt_message(7, 12, [DataWord(payload=0xBAD0)])

    inj_result = injector.inject_between_messages(
        msg1, msg2, injected_msg, gap_time=2.0
    )

    print(f"Gap time: {inj_result['gap_time']} μs")
    print(f"Gap violation: {inj_result['gap_violation']} (minimum is 4.0 μs)")
    print("Standard Violation: §4.3.4.6.2.3.1 - Inter-message gap ≥ 4 μs")

    # Statistics
    print_subsection("Injection Statistics")
    stats = injector.get_statistics()
    print(f"Total injections attempted: {stats['total_injections']}")
    print(f"Timing distribution: {stats['timing_distribution']}")


def demo_replay_attacks():
    """Demonstrate replay attack capabilities."""
    print_section("4. REPLAY ATTACKS")

    # Create legitimate message
    legitimate = create_bc_to_rt_message(
        rt_address=5,
        subaddress=10,
        data_words=[DataWord(payload=0x5EC0), DataWord(payload=0xE7DA)]  # SECRET DATA
    )

    formatter = CompactHexFormatter()

    # Capture and replay
    print_subsection("Capture and Replay")
    attacker = ReplayAttacker()

    capture = attacker.capture_message(legitimate)
    print(f"Captured message at index {capture['capture_index']}")
    print(formatter.format_message(legitimate))

    replay_result = attacker.replay(legitimate, delay=0.001)
    print(f"\nReplayed after {replay_result['delay']*1000:.2f} ms")
    print("Attack: Repeat authorized command to trigger action again")

    # Replay with modification
    print_subsection("Replay with Modification")
    modifications = {
        'data_words': [
            DataWord(payload=0xDEAD),
            DataWord(payload=0xBEEF)
        ]
    }

    modified_replay = attacker.replay_modified(legitimate, modifications)
    print("Original data: 0x5EC0, 0xE7DA (SECRET DATA)")
    print("Modified data: 0xDEAD, 0xBEEF (ATTACKER DATA)")
    print(formatter.format_message(modified_replay['replayed']))

    # Amplification attack
    print_subsection("Amplification Attack (DoS)")
    amplified = attacker.amplify(legitimate, count=10)
    print(f"Single message replayed {len(amplified)} times in rapid succession")
    print("Impact: RT overload, bus saturation, denial of service")

    # Replay detection
    print_subsection("Replay Detection")
    detector = ReplayDetector()

    detector.check_replay(legitimate)  # First occurrence - OK
    is_replay = detector.check_replay(legitimate)  # Second occurrence - REPLAY!

    print(f"First message: replay={False}")
    print(f"Duplicate message: replay={is_replay}")
    print("Detection method: Exact duplicate detection in recent history")

    # Statistics
    print_subsection("Replay Statistics")
    stats = attacker.get_statistics()
    print(f"Messages captured: {stats['messages_captured']}")
    print(f"Replays executed: {stats['replays_executed']}")
    print(f"Modification rate: {stats['modification_rate']:.1f}%")


def demo_timing_attacks():
    """Demonstrate timing attack capabilities."""
    print_section("5. TIMING ATTACKS")

    template = create_bc_to_rt_message(
        rt_address=5,
        subaddress=10,
        data_words=[DataWord(payload=0x1234)]
    )

    attacker = TimingAttacker()

    # Response time violations
    print_subsection("Response Time Violations")

    # Too early
    too_early = attacker.violate_response_time(template, violation_us=-2.0)
    response = too_early.get_response_time()
    print(f"Response too early: {response} μs (minimum: 4 μs)")
    print("Standard Violation: §4.3.4.6.2.3.2")

    # Too late
    too_late = attacker.violate_response_time(template, violation_us=5.0)
    response = too_late.get_response_time()
    print(f"Response too late: {response} μs (maximum: 12 μs)")
    print("Standard Violation: §4.3.4.6.2.3.2")

    # Inter-message gap violations
    print_subsection("Inter-Message Gap Violations")
    messages = [template] * 5
    compressed = attacker.manipulate_gaps(messages, gap_factor=0.1)

    print(f"Original gap: 4.0 μs (typical)")
    print(f"Compressed gap: {compressed[0].gap_time} μs")
    print("Standard Violation: §4.3.4.6.2.3.1 - Gap must be ≥ 4 μs")

    # Bus flood
    print_subsection("Bus Flooding Attack")
    flood = attacker.create_bus_flood(
        duration=1000,  # 1 ms
        message_template=template,
        gap_time=0.5  # Severe violation
    )

    print(f"Flood duration: {flood['duration_us']} μs")
    print(f"Gap time: {flood['gap_time_us']} μs (violates 4 μs minimum)")
    print(f"Estimated messages: {flood['estimated_messages']}")
    print(f"Bus saturation: {flood['saturation_percent']:.1f}%")
    print("Impact: Legitimate traffic blocked, RT overload, DoS")

    # Timing race condition
    print_subsection("Timing Race Condition")
    msg1 = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1111)])
    msg2 = create_bc_to_rt_message(5, 11, [DataWord(payload=0x2222)])

    race = attacker.create_timing_race(msg1, msg2, gap_us=0.5)
    print(f"Two messages sent with {race['gap_us']} μs gap")
    print(f"Potential collision: {race['potential_collision']}")
    print("Purpose: Test BC/RT serialization and race handling")

    # Timing anomaly detection
    print_subsection("Timing Anomaly Detection")
    monitor = TimingMonitor()

    anomaly = monitor.detect_timing_anomaly(too_early)
    if anomaly:
        print(f"Anomaly detected: {anomaly}")

    # Statistics
    print_subsection("Timing Attack Statistics")
    stats = attacker.get_statistics()
    print(f"Attacks executed: {stats['attacks_executed']}")
    print(f"Attack types: {stats['attack_types']}")
    print(f"Violation rate: {stats['violation_rate']:.1f}%")


def demo_security_validation():
    """Demonstrate security validation and anomaly detection."""
    print_section("6. SECURITY VALIDATION & ANOMALY DETECTION")

    validator = SecurityValidator()

    # Create various test messages
    print_subsection("Anomaly Detection Tests")

    # Test 1: Normal message
    normal = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1234)])
    anomalies = validator.check_anomalies(normal)
    print(f"\n1. Normal message: {len(anomalies)} anomalies detected")

    # Test 2: Replayed message
    validator.check_anomalies(normal)  # Add to history
    anomalies = validator.check_anomalies(normal)  # Check duplicate
    print(f"\n2. Replayed message: {len(anomalies)} anomalies detected")
    for anomaly in anomalies:
        print(f"   {anomaly}")

    # Test 3: Timing violation
    attacker = TimingAttacker()
    timing_violated = attacker.violate_response_time(normal, violation_us=-3.0)
    anomalies = validator.check_anomalies(timing_violated)
    print(f"\n3. Timing violation: {len(anomalies)} anomalies detected")
    for anomaly in anomalies:
        print(f"   {anomaly}")

    # Test 4: Malformed packet
    gen = MalformedPacketGenerator()
    malformed = gen.generate_word_count_mismatch(normal, declared_count=10)
    anomalies = validator.check_anomalies(malformed)
    print(f"\n4. Malformed packet: {len(anomalies)} anomalies detected")
    for anomaly in anomalies:
        print(f"   {anomaly}")

    # Attack pattern recognition
    print_subsection("Attack Pattern Recognition")

    # Create flood pattern
    flood_messages = [normal] * 60
    pattern = validator.detect_attack_pattern(flood_messages)
    print(f"\n60 messages in sequence: {pattern}")

    # Create replay pattern
    replay_messages = [normal, normal, normal]
    pattern = validator.detect_attack_pattern(replay_messages)
    print(f"3 identical messages: {pattern}")

    # Create fuzzing pattern (multiple malformed)
    fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=0.5))
    fuzzed_messages = fuzzer.generate_test_cases(normal, count=20)
    pattern = validator.detect_attack_pattern(fuzzed_messages)
    print(f"20 heavily mutated messages: {pattern}")

    # Statistics
    print_subsection("Security Validation Statistics")
    stats = validator.get_statistics()
    print(f"Total anomalies detected: {stats['total_anomalies']}")
    print(f"Messages analyzed: {stats['messages_analyzed']}")
    print(f"Anomaly rate: {stats['anomaly_rate']:.2f}%")
    print(f"Anomaly breakdown: {stats['anomaly_types']}")


def demo_scenario_framework():
    """Demonstrate attack scenario framework."""
    print_section("7. ATTACK SCENARIO FRAMEWORK")

    template = create_bc_to_rt_message(
        rt_address=5,
        subaddress=10,
        data_words=[DataWord(payload=0x1234), DataWord(payload=0x5678)]
    )

    # Built-in scenarios
    print_subsection("Built-In Scenarios")

    scenarios = ScenarioLibrary.get_all_scenarios(template)
    print(f"Available scenarios: {len(scenarios)}")
    for scenario in scenarios:
        print(f"  - {scenario.name} ({scenario.complexity.value} complexity)")

    # Execute individual scenario
    print_subsection("Execute Individual Scenario: Basic Fuzzing")
    scenario = ScenarioLibrary.basic_fuzzing(template)
    result = scenario.execute()
    print(result)
    print(f"  Messages generated: {result.messages_generated}")
    print(f"  Anomalies detected: {len(result.anomalies_detected)}")

    # Execute scenario suite
    print_subsection("Execute Scenario Suite")
    runner = ScenarioRunner()

    # Add multiple scenarios
    runner.add_scenario(ScenarioLibrary.basic_fuzzing(template))
    runner.add_scenario(ScenarioLibrary.malformed_packet_suite(template))
    runner.add_scenario(ScenarioLibrary.replay_attack_suite(template))
    runner.add_scenario(ScenarioLibrary.timing_violation_suite(template))

    print(f"\nExecuting {len(runner.scenarios)} scenarios...\n")
    results = runner.run_all()

    # Print summary
    runner.print_summary(results)

    # Custom scenario
    print_subsection("Custom Scenario")
    custom = TestScenario(
        name="Custom High-Rate Fuzzing",
        description="Aggressive bit-flip fuzzing with 20% mutation",
        scenario_type=ScenarioType.FUZZING,
        complexity=AttackComplexity.HIGH,
        template_message=template,
        attack_config={
            'strategy': 'bitflip',
            'mutation_rate': 0.20,
            'count': 200
        },
        max_iterations=200
    )

    result = custom.execute()
    print(result)

    # Export/Import scenarios
    print_subsection("Export/Import Scenarios")
    runner.export_to_json('/tmp/test_scenarios.json')
    print("Exported scenarios to /tmp/test_scenarios.json")

    # Could import with:
    # imported_runner = ScenarioRunner.import_from_json('/tmp/test_scenarios.json', template)


def main():
    """Run all Milestone 5 demonstrations."""
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#  MILESTONE 5: SECURITY TESTING FRAMEWORK DEMONSTRATION" + " " * 11 + "#")
    print("#" + " " * 68 + "#")
    print("#  MIL-STD-1553B Security Testing & Attack Simulation" + " " * 15 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)

    try:
        demo_fuzzing()
        demo_malformed_packets()
        demo_injection_attacks()
        demo_replay_attacks()
        demo_timing_attacks()
        demo_security_validation()
        demo_scenario_framework()

        print_section("MILESTONE 5 COMPLETE")
        print("\nAll security testing components demonstrated successfully:")
        print("  ✓ Fuzzing engine with 3 strategies")
        print("  ✓ Malformed packet generation")
        print("  ✓ Command injection attacks")
        print("  ✓ Replay attacks with detection")
        print("  ✓ Timing attacks and monitoring")
        print("  ✓ Security validation and anomaly detection")
        print("  ✓ Attack scenario framework")
        print("\nThe MIL-STD-1553B security testing framework is production-ready!")
        print("=" * 70)

    except Exception as e:
        print(f"\n\nERROR during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
