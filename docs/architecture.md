# MIL-STD-1553B Packet Engine Architecture

## Overview

This document describes the architecture of the MIL-STD-1553B Security Testing Packet Engine and its mapping to the MIL-STD-1553B protocol specification.

## MIL-STD-1553B Protocol Summary

**Standard**: MIL-STD-1553B (Notice 2, 1986)
**Title**: Aircraft Internal Time Division Command/Response Multiplex Data Bus
**Purpose**: Define mechanical, electrical, and functional characteristics of serial data bus for military aircraft

### Key Specifications

**Physical Layer (Section 4.3)**
- Dual redundant bus topology (Bus A and Bus B)
- Twisted shielded pair transmission line
- Transformer coupled stub connections
- 1 MHz ± 0.1% bit rate (MIL-STD-1553B §4.3.3.1.1)

**Data Encoding (Section 4.3.3.2)**
- Manchester II Bi-Phase encoding
- Logic 1: Low-to-High transition at bit center
- Logic 0: High-to-Low transition at bit center
- Self-clocking capability

**Word Structure (Section 4.3.5)**
- 20 bits total per word
- Structure: [Sync: 3 bits][Data: 16 bits][Parity: 1 bit]
- Odd parity over sync + data (19 bits)

## Architecture Components

### 1. Core Layer (`mil1553/core/`)

Maps directly to MIL-STD-1553B protocol specifications.

#### 1.1 Constants (`constants.py`)

**Standard References:**

```python
# MIL-STD-1553B §4.3.5.2.1 - Sync Patterns
class SyncPattern(IntEnum):
    COMMAND_STATUS = 0b100  # Command/Status sync (invalid for data)
    DATA = 0b000            # Data sync (invalid for command/status)
```

**Per §4.3.5.2.1**: "The synchronization waveform shall be unique and recognizable... shall not be produced by any combination of data and parity within the data field."

```python
# MIL-STD-1553B §4.3.5.1 - Message Types
class MessageType(Enum):
    BC_TO_RT = "bc_to_rt"          # §4.3.4.2.1
    RT_TO_BC = "rt_to_bc"          # §4.3.4.2.2
    RT_TO_RT = "rt_to_rt"          # §4.3.4.2.3
    MODE_COMMAND = "mode_command"  # §4.3.4.3
    BROADCAST = "broadcast"        # §4.3.4.4
```

```python
# MIL-STD-1553B §4.3.3.1.1 - Timing Constants
class TimingConstants:
    BIT_TIME = 1.0                    # 1 MHz ± 0.1%
    WORD_TIME = 20.0                  # 20 bits @ 1 MHz
    RESPONSE_TIME_MIN = 4.0           # §4.3.4.6.2.3.2
    RESPONSE_TIME_MAX = 12.0          # §4.3.4.6.2.3.2
    INTER_MESSAGE_GAP_MIN = 4.0       # §4.3.4.6.2.3.1
```

**Per §4.3.4.6.2.3.2**: "The RT shall respond... in not less than 4 microseconds and not more than 12 microseconds."

```python
# MIL-STD-1553B §4.3.5.2.1.1 - Mode Codes
class ModeCode(IntEnum):
    DYNAMIC_BUS_CONTROL = 0b00000      # §4.3.4.3.1
    SYNCHRONIZE = 0b00001              # §4.3.4.3.2
    TRANSMIT_STATUS_WORD = 0b00010     # §4.3.4.3.3
    INITIATE_SELF_TEST = 0b00011       # §4.3.4.3.4
    TRANSMITTER_SHUTDOWN = 0b00100     # §4.3.4.3.5
    # ... (additional mode codes per §4.3.4.3)
```

#### 1.2 Word Classes (`word.py`)

**Standard References:**

**Command Word (§4.3.5.2.2)**
```
┌──────┬────────────┬─────┬────────────┬─────────────┬────────┐
│ Sync │ RT Address │ T/R │ Subaddress │ Word Count/ │ Parity │
│      │  (5 bits)  │(1)  │  (5 bits)  │ Mode (5)    │  (1)   │
│ 3    │            │     │            │             │        │
└──────┴────────────┴─────┴────────────┴─────────────┴────────┘
```

- **RT Address**: 0-31 (31 = broadcast per §4.3.4.4)
- **T/R Bit**: 0 = Receive, 1 = Transmit
- **Subaddress**: 0-31 (0 or 31 = mode command per §4.3.4.3)
- **Word Count**: 0-31 (0 = 32 words per §4.3.5.2.2.4)

**Status Word (§4.3.5.2.3)**
```
┌──────┬────────────┬──────────────────────────────┬────────┐
│ Sync │ RT Address │      Status Flags (10)       │ Parity │
│ 3    │  (5 bits)  │                              │  (1)   │
└──────┴────────────┴──────────────────────────────┴────────┘
```

Status Flags (per §4.3.5.2.3):
- Bit 10: Message Error
- Bit 9: Instrumentation
- Bit 8: Service Request
- Bits 7-5: Reserved (shall be zero)
- Bit 4: Broadcast Received
- Bit 3: Busy
- Bit 2: Subsystem Flag
- Bit 1: Dynamic Bus Control Acceptance
- Bit 0: Terminal Flag

**Data Word (§4.3.5.2.4)**
```
┌──────┬────────────────────────────────┬────────┐
│ Sync │        Data (16 bits)          │ Parity │
│ 3    │                                │  (1)   │
└──────┴────────────────────────────────┴────────┘
```

#### 1.3 Parity Calculation (`parity.py`)

**Standard Reference: §4.3.5.2.1.2**

"The parity bit shall be chosen such that the total number of ones in the sync field, data field, and parity bit is odd (odd parity)."

Implementation:
```python
def calculate_word_parity_1553(sync: int, data: int) -> int:
    """Calculate parity over sync (3) + data (16) = 19 bits"""
    combined = (sync << 16) | data
    ones = count_ones(combined, 19)
    return 0 if (ones % 2 == 1) else 1  # Make total odd
```

#### 1.4 Manchester Encoding (`encoding.py`)

**Standard Reference: §4.3.3.2**

"Data shall be transmitted using bi-phase Manchester II code format."

**Encoding Rules (§4.3.3.2.1)**:
- Logic 0: High-to-Low transition at bit center
- Logic 1: Low-to-High transition at bit center
- Bit period: 1.0 μs ± 0.1%

Implementation:
```python
class ManchesterEncoder:
    @staticmethod
    def encode_bit(bit: int) -> bytes:
        if bit == 0:
            return bytes([0b10])  # High-to-Low
        elif bit == 1:
            return bytes([0b01])  # Low-to-High
```

### 2. Message Layer (`mil1553/core/message.py`)

**Standard References:**

#### 2.1 Message Types

**BC-to-RT (§4.3.4.2.1)**
- Format: [Command Word] [Data Words]
- BC transmits command and data to RT
- No status response for broadcast

**RT-to-BC (§4.3.4.2.2)**
- Format: [Command Word] [Status Word] [Data Words]
- RT transmits status and data to BC
- Response time: 4-12 μs (§4.3.4.6.2.3.2)

**RT-to-RT (§4.3.4.2.3)**
- Format: [RX Command] [TX Command] [RX Status] [Data] [TX Status]
- Two RTs involved in transfer
- Receiving RT responds first

**Mode Command (§4.3.4.3)**
- Format: [Command Word] [Status Word] [Optional Data]
- Subaddress = 0 or 31 indicates mode command
- 20 defined mode codes

**Broadcast (§4.3.4.4)**
- Format: [Command Word (RT=31)] [Data Words]
- No status response
- All RTs receive

### 3. Validation Layer (`mil1553/core/validation.py`)

Maps to protocol compliance requirements throughout MIL-STD-1553B.

**Protocol Checks:**

1. **Parity Validation (§4.3.5.2.1.2)**
   - Verify odd parity over sync + data
   - Severity: HIGH

2. **Sync Pattern (§4.3.5.2.1)**
   - Command/Status: 0b100
   - Data: 0b000
   - Severity: HIGH

3. **Address Range (§4.3.5.2.2.1)**
   - RT Address: 0-31
   - Broadcast: 31
   - Severity: CRITICAL

4. **Timing Compliance (§4.3.4.6)**
   - RT Response: 4-12 μs
   - Inter-message Gap: ≥ 4 μs
   - Severity: MEDIUM

5. **Word Count (§4.3.5.2.2.4)**
   - Declared vs actual match
   - 0 = 32 words
   - Severity: HIGH

### 4. Device Layer (`mil1553/devices/`)

Maps to §4.3.4.1 - Terminal Types

#### 4.1 Bus Controller (BC) - §4.3.4.1.1

"The BC shall initiate all data transfers on the bus."

Responsibilities:
- Schedule all message transfers
- Poll remote terminals
- Handle mode commands
- Manage bus arbitration

#### 4.2 Remote Terminal (RT) - §4.3.4.1.2

"The RT shall interface directly with a subsystem."

Responsibilities:
- Respond to BC commands within 4-12 μs
- Provide status information
- Manage subaddresses (up to 32)
- Handle mode commands

#### 4.3 Bus Monitor (BM) - §4.3.4.1.3

"The BM is a passive receive-only terminal."

Responsibilities:
- Capture all bus traffic
- No transmission capability
- Traffic analysis
- Anomaly detection

### 5. Security Testing Layer (`mil1553/security/`)

Extends protocol implementation for security testing.

#### 5.1 Fuzzing Engine

**Attack Vectors:**
- Bit flipping in protocol fields
- Boundary value testing
- Invalid field combinations
- Timing violations

#### 5.2 Attack Modules

**Injection Attacks:**
- Unauthorized BC commands (violates §4.3.4.1.1)
- Address spoofing
- Mode command injection

**Replay Attacks:**
- Message capture and retransmission
- Timing manipulation
- Modified replay

**Timing Attacks:**
- Response time violations (§4.3.4.6.2.3.2)
- Gap time violations (§4.3.4.6.2.3.1)
- Bus flooding

**Malformed Packets:**
- Invalid sync patterns (§4.3.5.2.1)
- Parity errors (§4.3.5.2.1.2)
- Invalid addresses (§4.3.5.2.2.1)
- Word count mismatches

### 6. Output Layer (`mil1553/output/`)

Provides visualization and analysis tools.

**Formatters:**
- **Binary**: Raw wire format
- **Hex**: Traditional hex dump
- **Annotated**: Field-level annotations with standard references
- **Visual**: ASCII art visualization
- **JSON**: Machine-readable format
- **Compact**: One-line logging

## Data Flow

### Encoding Pipeline

```
User Input → Message Construction → Word Generation → Encoding → Wire Format
                                         ↓
                                   Parity Calculation
                                         ↓
                                   Protocol Validation
                                         ↓
                                   Manchester Encoding
                                         ↓
                                   Binary Output (1 MHz)
```

### Decoding Pipeline

```
Wire Format → Manchester Decoding → Word Parsing → Message Assembly → Validation
                                         ↓
                                   Sync Detection
                                         ↓
                                   Parity Verification
                                         ↓
                                   Field Extraction
                                         ↓
                                   Protocol Compliance
```

## Security Testing Architecture

### Threat Model

1. **Unauthorized Commands**
   - Non-BC device transmitting commands
   - Violates exclusive BC control (§4.3.4.1.1)

2. **Timing Attacks**
   - Response time violations
   - Bus contention/flooding

3. **Protocol Violations**
   - Invalid sync/parity
   - Malformed messages

4. **Replay Attacks**
   - Captured message retransmission
   - Command reordering

### Security Testing Capabilities

1. **Packet Crafting**
   ```python
   # Create protocol-compliant packet
   cmd = CommandWord(rt_address=5, transmit_receive=0, ...)

   # Inject faults
   corrupted = cmd.corrupt_parity()    # Parity violation
   bad_sync = cmd.corrupt_sync()       # Sync violation
   ```

2. **Fuzzing**
   ```python
   fuzzer = Fuzzer(strategy=BitFlipFuzzer())
   test_cases = fuzzer.generate_test_cases(count=1000)
   ```

3. **Attack Simulation**
   ```python
   attacker = CommandInjector()
   attacker.inject_command(malicious_cmd, timing='between_messages')
   ```

## Standard Compliance Matrix

| Component | Standard Section | Compliance | Notes |
|-----------|-----------------|------------|-------|
| Bit Rate | §4.3.3.1.1 | Full | 1 MHz ± 0.1% |
| Manchester Encoding | §4.3.3.2 | Full | Bi-phase Mark |
| Sync Patterns | §4.3.5.2.1 | Full | 0b100 / 0b000 |
| Parity | §4.3.5.2.1.2 | Full | Odd parity |
| Command Word | §4.3.5.2.2 | Full | All fields |
| Status Word | §4.3.5.2.3 | Full | All flags |
| Data Word | §4.3.5.2.4 | Full | 16-bit payload |
| Message Types | §4.3.4 | Full | All 5 types |
| Timing | §4.3.4.6 | Full | All constraints |
| Mode Codes | §4.3.4.3 | Partial | Core codes |

## References

1. **MIL-STD-1553B (Notice 2)**: Aircraft Internal Time Division Command/Response Multiplex Data Bus, Department of Defense, 21 September 1978 (Notice 2: 23 February 1980)

2. **MIL-STD-1553 Designer's Guide**: Guidelines and design considerations for MIL-STD-1553 implementation

3. **SAE AS5652**: MIL-STD-1553 Design and Validation Test Plan

4. **DO-178C**: Software Considerations in Airborne Systems and Equipment Certification (for safety-critical implementations)

## Glossary

- **BC**: Bus Controller - Controls all bus communications
- **RT**: Remote Terminal - Subsystem interface
- **BM**: Bus Monitor - Passive traffic observer
- **T/R**: Transmit/Receive bit in command word
- **SA**: Subaddress (0-31)
- **WC**: Word Count (0-31, where 0 = 32)
- **Manchester II**: Bi-phase encoding method
- **Stub**: Transformer-coupled bus connection

## Version History

- v0.1.0 (2025-12-31): Initial implementation
  - Core protocol support
  - Message encoding/decoding
  - Manchester II encoding
  - Output formatters
  - Security testing framework
