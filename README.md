# ✈️ Turbofuzz-1553

> *"Because your avionics bus deserves a proper stress test"*

A turbocharged security testing framework for MIL-STD-1553B (The military aircraft data bus). Think fuzzing, but with more G-forces! 🚀

## What is this thing?

Turbofuzz-1553 is a Python-based packet crafting and security testing engine for MIL-STD-1553B, the data bus standard used in military aircraft, spacecraft, and other critical systems. It lets you:

- 🎯 **Craft compliant packets** - Build proper BC-to-RT, RT-to-BC, RT-to-RT, mode commands, and broadcasts
- 💥 **Fuzz the living daylights** - Bit-flip, boundary value, and semantic fuzzing strategies
- 🔨 **Launch attacks** - Command injection, replay, timing violations, malformed packets
- 🛡️ **Validate security** - Detect anomalies and attack patterns
- 🎬 **Run scenarios** - Pre-built and custom attack scenarios

All without needing actual hardware! Perfect for security researchers, aerospace engineers, or anyone who thinks "What if I send an invalid sync pattern?" is a fun Friday night.

## Quick Start

### Installation

```bash
git clone https://github.com/yourusername/turbofuzz-1553.git
cd turbofuzz-1553
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Your First Flight ✈️

```python
from mil1553.core.word import DataWord
from mil1553.core.message import create_bc_to_rt_message
from mil1553.security.fuzzer import Fuzzer, BitFlipFuzzer

# Create a legitimate message
msg = create_bc_to_rt_message(
    rt_address=5,
    subaddress=10,
    data_words=[DataWord(payload=0x1234)]
)

# Now let's get chaotic
fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=0.1))
chaos = fuzzer.generate_test_cases(msg, count=100)

print(f"Generated {len(chaos)} potentially catastrophic test cases!")
```

## Demo Flights 🛫

Run the milestone demos to see everything in action:

```bash
# Milestone 1: Word creation and manipulation
python examples/milestone1_demo.py

# Milestone 2: Encoding/decoding pipeline (Manchester II baby!)
python examples/milestone2_demo.py

# Milestone 3: Pretty-print your packets
python examples/milestone3_demo.py

# Milestone 5: Full security testing suite (BUCKLE UP!)
python examples/milestone5_demo.py
```

The Milestone 5 demo is the full security testing experience:
- ✓ 3 fuzzing strategies
- ✓ Malformed packet generation
- ✓ Command injection attacks
- ✓ Replay attacks with detection
- ✓ Timing attacks and bus flooding
- ✓ 245 anomalies detected across 172 test messages

## Features

### Protocol Implementation ✅

Full MIL-STD-1553B compliance:
- 20-bit word structure (3-bit sync + 16-bit data + 1-bit parity)
- Manchester II (bi-phase) encoding at 1 MHz
- Command, Status, and Data words
- All 5 message types
- Timing validation (response times, inter-message gaps)

### Security Testing Arsenal 🔥

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

### Output Formats 📊

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
│   ├── devices/       # BC, RT, BM simulation (WIP)
│   ├── parser/        # Encoding/decoding
│   ├── security/      # Attack modules & fuzzing
│   ├── output/        # Formatters
│   └── utils/         # Bit ops, parity, timing
├── tests/             # Unit & integration tests
├── examples/          # Runnable demos
└── docs/              # Architecture & security guide
```

## Documentation 📚

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

## Warning ⚠️

This tool is for **authorized security testing only**. Don't use it on production avionics systems unless you want to explain to the FAA why the autopilot thinks it's a toaster.

## Contributing

Found a bug? Want to add a new attack vector? PRs welcome! Just remember:
1. Keep it silly (aviation puns encouraged)
2. Keep it secure (no actual malware)
3. Keep it tested (we're not barbarians)

## License

MIT License - Fly free! ✈️

## Credits

Built with ☕ and a healthy fear of edge cases.

Special thanks to:
- The engineers who wrote MIL-STD-1553B
- Coffee, for existing
- That one fuzzer that found the weird bug

---

*"In case of emergency, the nearest exit may be behind you, above you, or in a completely invalid memory address."*
