# Turbofuzz-1553

## MIL-STD-1553B Security Testing Framework

Turbofuzz-1553 is a comprehensive Python-based security testing framework for MIL-STD-1553B, the data bus protocol used in military aircraft, spacecraft, and other safety-critical avionics systems. This framework provides protocol-compliant packet generation, fuzzing capabilities, attack simulation, and vulnerability assessment tools.

## Overview

This framework enables security researchers and aerospace engineers to:

- **Generate protocol-compliant packets** - Create BC-to-RT, RT-to-BC, RT-to-RT transfers, mode commands, and broadcast messages
- **Perform security testing** - Implement bit-flip, boundary value, and semantic fuzzing strategies
- **Simulate attack vectors** - Test command injection, replay attacks, timing violations, and malformed packet handling
- **Validate implementations** - Detect anomalies, recognize attack patterns, and assess security posture
- **Execute test scenarios** - Utilize pre-built attack scenarios or develop custom test cases

The framework includes a complete software-based bus simulation, enabling testing without physical hardware.

## Quick Start

### Installation

```bash
git clone https://github.com/SpaceHackn/turbofuzz-1553.git
cd turbofuzz-1553
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Basic Usage Example

```python
from mil1553.core.word import DataWord
from mil1553.core.message import create_bc_to_rt_message
from mil1553.security.fuzzer import Fuzzer, BitFlipFuzzer

# Create a protocol-compliant message
message = create_bc_to_rt_message(
    rt_address=5,
    subaddress=10,
    data_words=[DataWord(payload=0x1234)]
)

# Generate fuzzed test cases
fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=0.1))
test_cases = fuzzer.generate_test_cases(message, count=100)

print(f"Generated {len(test_cases)} test cases for security validation")
```

## Examples and Demonstrations

The framework includes comprehensive demonstrations of all capabilities:

```bash
# Protocol implementation examples
python examples/milestone1_demo.py  # Word creation and manipulation
python examples/milestone2_demo.py  # Encoding/decoding pipeline
python examples/milestone3_demo.py  # Output formatting

# Device simulation
python examples/milestone4_demo.py  # Virtual bus with BC, RT, BM devices

# Security testing
python examples/milestone5_demo.py  # Complete security testing suite
```

### Example Capabilities

**Device Simulation (Milestone 4):**
- Bus Controller (BC) implementation
- Remote Terminal (RT) simulation with configurable subaddresses
- Bus Monitor (BM) for traffic analysis
- Virtual bus enabling hardware-independent testing

**Security Testing (Milestone 5):**
- Three fuzzing strategies (bit-flip, boundary value, semantic)
- Malformed packet generation with protocol violations
- Command injection attack simulation
- Replay attack capabilities with detection mechanisms
- Timing attack vectors including bus flooding
- Comprehensive anomaly detection (245 anomalies across 172 test messages in demonstration)

## Features

### Protocol Implementation

Full MIL-STD-1553B compliance:
- 20-bit word structure (3-bit sync + 16-bit data + 1-bit parity)
- Manchester II (bi-phase) encoding at 1 MHz
- Command, Status, and Data words
- All 5 message types
- Timing validation (response times, inter-message gaps)

### Security Testing Capabilities

**Fuzzing Engine:**
- `BitFlipFuzzer` - Random bit corruption
- `BoundaryFuzzer` - Edge case testing (0, 1, max, max+1, etc.)
- `SemanticFuzzer` - Protocol violations with structure

**Attack Modules:**
- `CommandInjector` - Unauthorized command injection (§4.3.4.1.1 violation)
- `ReplayAttacker` - Message capture and replay with modifications
- `TimingAttacker` - Response time violations, bus flooding, race conditions
- `MalformedPacketGenerator` - Invalid sync, parity errors, word count mismatches

**Validation:**
- `SecurityValidator` - Anomaly detection beyond protocol compliance
- Attack pattern recognition (replay, flood, fuzzing)
- Confidence scoring for detected anomalies

**Scenario Framework:**
- 8 pre-built attack scenarios
- Custom scenario creation
- JSON import/export
- Multi-scenario orchestration

### Output Formats

- Binary (raw wire format)
- Hex dump
- Annotated hex (with field labels)
- Compact (one-line for logging)
- Visual (ASCII art)
- JSON (machine-readable)

## Architecture

```
turbofuzz-1553/
├── mil1553/
│   ├── core/          # Protocol fundamentals
│   ├── devices/       # BC, RT, BM simulation
│   ├── parser/        # Encoding/decoding
│   ├── security/      # Attack modules & fuzzing
│   ├── output/        # Formatters
│   └── utils/         # Bit ops, parity, timing
├── tests/             # Unit & integration tests
├── examples/          # Runnable demos
└── docs/              # Architecture & security guide
```

The framework includes a complete virtual 1553 bus simulation:
- Software-based Bus Controller, Remote Terminals, and Bus Monitor
- Simulate entire 1553 networks without hardware
- Test attacks against simulated devices
- Suitable for education, development, and testing

## Documentation

- [Architecture Guide](docs/architecture.md) - Complete system architecture with standard references
- [Security Testing Guide](docs/security_testing_guide.md) - Attack methodologies and best practices

## Standard Compliance

All attack vectors mapped to specific MIL-STD-1553B violations:
- §4.3.4.1.1: BC command authority (injection attacks)
- §4.3.4.6.2.3.1: Inter-message gap ≥ 4 μs (timing attacks)
- §4.3.4.6.2.3.2: RT response 4-12 μs (timing attacks)
- §4.3.5.2.1: Sync pattern validation (malformed packets)
- §4.3.5.2.2.4: Word count consistency (malformed packets)

## Use Cases

- **Security Research**: Find vulnerabilities in 1553B implementations
- **Aerospace Testing**: Validate avionics systems against edge cases
- **CTF Challenges**: Create realistic aerospace security challenges
- **Education**: Learn about safety-critical bus protocols

## Disclaimer

This tool is designed for **authorized security testing, research, and educational purposes only**. Use on production avionics systems or operational aircraft is prohibited without proper authorization and regulatory compliance. Users are solely responsible for ensuring appropriate use within legal and regulatory frameworks.

## Contributing

Contributions are welcome. When submitting pull requests, please ensure:
1. Code follows existing architecture and style guidelines
2. Security testing code is for research purposes only
3. All contributions include appropriate unit tests
4. Documentation is updated to reflect changes

## License

MIT License

## Acknowledgments

This framework was developed for security research and aerospace testing applications.

Special acknowledgment to:
- The engineers who developed the MIL-STD-1553B standard
- The aerospace security research community
- Contributors to this project
