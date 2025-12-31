#!/usr/bin/env python3
"""
Milestone 4 Demo: Device Simulation

Demonstrates the complete virtual 1553 bus simulation with BC, RT, and BM devices.
Shows how devices can communicate without any physical hardware!
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mil1553.devices import (
    VirtualBus,
    BusController,
    RemoteTerminal,
    BusMonitor
)
from mil1553.core.word import DataWord
from mil1553.core.constants import ModeCode


def print_section(title: str):
    """Print section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_basic_communication():
    """Demonstrate basic BC-RT communication."""
    print_section("1. BASIC BC-RT COMMUNICATION")

    # Create virtual bus
    bus = VirtualBus()

    # Create devices
    bc = BusController(name="FlightComputer")
    rt1 = RemoteTerminal(rt_address=5, name="NavSensor")
    rt2 = RemoteTerminal(rt_address=6, name="Actuator")

    # Connect to bus
    bus.connect(bc)
    bus.connect(rt1)
    bus.connect(rt2)

    print(f"\nCreated virtual bus with {len(bus.devices)} devices:")
    for device in bus.devices.values():
        print(f"  - {device}")

    # BC sends data to RT
    print("\n--- BC-to-RT Transfer ---")
    print(f"BC sending data to RT 5...")

    status = bc.send_to_rt(
        rt_address=5,
        subaddress=10,
        data=[
            DataWord(payload=0x1234),
            DataWord(payload=0x5678)
        ]
    )

    if status:
        print(f"✓ RT 5 responded with status: {status.to_hex()}")
        print(f"  Message Error: {status.message_error}")
        print(f"  Busy: {status.busy}")
    else:
        print("✗ No response from RT")

    # BC receives data from RT
    print("\n--- RT-to-BC Transfer ---")

    # First, set some data in RT's subaddress
    rt1.set_subaddress_data(
        subaddress=12,
        data=[
            DataWord(payload=0xABCD),
            DataWord(payload=0xDEAD),
            DataWord(payload=0xBEEF)
        ]
    )

    print(f"BC requesting data from RT 5, subaddress 12...")
    response = bc.receive_from_rt(
        rt_address=5,
        subaddress=12,
        word_count=3
    )

    if response and response.data_words:
        print(f"✓ Received {len(response.data_words)} words:")
        for i, word in enumerate(response.data_words):
            print(f"  Word {i}: 0x{word.payload:04X}")
    else:
        print("✗ No data received")

    # Statistics
    print("\n--- Device Statistics ---")
    for device in bus.devices.values():
        stats = device.get_statistics()
        print(f"{stats['name']:15s} | TX: {stats['messages_sent']:3d} | RX: {stats['messages_received']:3d}")


def demo_bus_monitor():
    """Demonstrate bus monitoring capabilities."""
    print_section("2. BUS MONITORING")

    bus = VirtualBus()
    bc = BusController(name="BC")
    rt1 = RemoteTerminal(rt_address=5, name="Sensor1")
    rt2 = RemoteTerminal(rt_address=6, name="Sensor2")
    bm = BusMonitor(name="Analyzer")

    bus.connect(bc)
    bus.connect(rt1)
    bus.connect(rt2)
    bus.connect(bm)

    print(f"\nBus Monitor connected. Capturing traffic...")

    # Generate some traffic
    for i in range(5):
        bc.send_to_rt(
            rt_address=5,
            subaddress=10,
            data=[DataWord(payload=0x1000 + i)]
        )

        bc.send_to_rt(
            rt_address=6,
            subaddress=11,
            data=[DataWord(payload=0x2000 + i)]
        )

    # Analyze captured traffic
    print(f"\n✓ Bus Monitor captured {len(bm.captured_messages)} messages")

    bm.print_analysis()

    # Filter by RT
    rt5_messages = bm.get_messages_by_rt(rt_address=5)
    print(f"\nMessages involving RT 5: {len(rt5_messages)}")


def demo_broadcast():
    """Demonstrate broadcast messaging."""
    print_section("3. BROADCAST MESSAGING")

    bus = VirtualBus()
    bc = BusController(name="BC")

    # Create multiple RTs
    rts = []
    for i in range(1, 6):
        rt = RemoteTerminal(rt_address=i, name=f"RT{i}")
        rts.append(rt)
        bus.connect(rt)

    bus.connect(bc)

    print(f"\nCreated bus with {len(rts)} RTs")

    # Broadcast time sync to all RTs
    print("\n--- Broadcasting Time Sync ---")
    bc.broadcast(
        subaddress=30,  # Time sync subaddress
        data=[
            DataWord(payload=0x1234),  # Time high
            DataWord(payload=0x5678)   # Time low
        ]
    )

    print("✓ Broadcast sent (no responses expected)")

    # Check that all RTs received it
    print("\nChecking RT broadcast flags:")
    for rt in rts:
        print(f"  RT {rt.rt_address}: broadcast_received={rt.broadcast_received}")


def demo_mode_commands():
    """Demonstrate mode commands."""
    print_section("4. MODE COMMANDS")

    bus = VirtualBus()
    bc = BusController(name="BC")
    rt = RemoteTerminal(rt_address=5, name="Sensor")

    bus.connect(bc)
    bus.connect(rt)

    # Send synchronize mode command
    print("\n--- Synchronize Mode Command ---")
    status = bc.send_mode_command(
        rt_address=5,
        mode_code=ModeCode.SYNCHRONIZE
    )

    if status:
        print(f"✓ RT synchronized")
        print(f"  Status: {status.to_hex()}")

    # Transmit status word mode command
    print("\n--- Transmit Status Word ---")
    status = bc.send_mode_command(
        rt_address=5,
        mode_code=ModeCode.TRANSMIT_STATUS_WORD
    )

    if status:
        print(f"✓ Received status word: {status.to_hex()}")


def demo_rt_handlers():
    """Demonstrate custom RT subaddress handlers."""
    print_section("5. CUSTOM RT HANDLERS")

    bus = VirtualBus()
    bc = BusController(name="BC")
    rt = RemoteTerminal(rt_address=5, name="SmartSensor")

    bus.connect(bc)
    bus.connect(rt)

    # Define custom handlers
    sensor_value = [0]  # Simulated sensor

    def on_receive(data):
        """Called when RT receives data."""
        print(f"  → RT received: {[f'0x{d.payload:04X}' for d in data]}")

    def on_transmit():
        """Called when RT needs to transmit data."""
        sensor_value[0] += 1
        print(f"  ← RT transmitting sensor value: {sensor_value[0]}")
        return [DataWord(payload=sensor_value[0])]

    # Set handlers
    rt.set_subaddress_handler(
        subaddress=10,
        receive_handler=on_receive,
        transmit_handler=on_transmit
    )

    print("\nConfigured RT with custom handlers")

    # Test receive handler
    print("\n--- Testing Receive Handler ---")
    bc.send_to_rt(
        rt_address=5,
        subaddress=10,
        data=[DataWord(payload=0xCAFE), DataWord(payload=0xBABE)]
    )

    # Test transmit handler
    print("\n--- Testing Transmit Handler ---")
    for i in range(3):
        response = bc.receive_from_rt(
            rt_address=5,
            subaddress=10,
            word_count=1
        )


def demo_scheduled_communication():
    """Demonstrate scheduled BC communication."""
    print_section("6. SCHEDULED BC COMMUNICATION")

    bus = VirtualBus()
    bc = BusController(name="BC")
    rt1 = RemoteTerminal(rt_address=5, name="Sensor1")
    rt2 = RemoteTerminal(rt_address=6, name="Sensor2")
    bm = BusMonitor(name="Monitor")

    bus.connect(bc)
    bus.connect(rt1)
    bus.connect(rt2)
    bus.connect(bm)

    # Set up RT data
    rt1.set_subaddress_data(12, [DataWord(payload=0x1111)])
    rt2.set_subaddress_data(13, [DataWord(payload=0x2222)])

    # Schedule periodic transfers
    print("\nScheduling periodic communication:")
    print("  - Poll RT 5 every 1000 μs")
    print("  - Poll RT 6 every 2000 μs")

    bc.add_to_schedule(
        rt_address=5,
        subaddress=12,
        transmit=True,  # RT transmits to BC
        interval_us=1000
    )

    bc.add_to_schedule(
        rt_address=6,
        subaddress=13,
        transmit=True,
        interval_us=2000
    )

    # Execute schedule
    print("\nExecuting schedule for 0.01 seconds...")
    bc.execute_schedule(duration_s=0.01)

    print(f"\n✓ Schedule executed")
    print(f"  BC sent {bc.statistics.messages_sent} messages")
    print(f"  RT 5 responded {rt1.statistics.messages_sent} times")
    print(f"  RT 6 responded {rt2.statistics.messages_sent} times")
    print(f"  Monitor captured {len(bm.captured_messages)} messages")


def demo_error_conditions():
    """Demonstrate RT error conditions."""
    print_section("7. RT ERROR CONDITIONS")

    bus = VirtualBus()
    bc = BusController(name="BC")

    # Create RT with error probability
    rt_faulty = RemoteTerminal(
        rt_address=5,
        name="FaultySensor",
        busy_probability=0.3,    # 30% chance of busy
        error_probability=0.2    # 20% chance of error
    )

    bus.connect(bc)
    bus.connect(rt_faulty)

    print("\nCreated RT with:")
    print("  - 30% busy probability")
    print("  - 20% error probability")

    print("\nSending 10 commands...")

    error_count = 0
    busy_count = 0

    for i in range(10):
        status = bc.send_to_rt(
            rt_address=5,
            subaddress=10,
            data=[DataWord(payload=i)]
        )

        if status:
            if status.message_error:
                error_count += 1
                print(f"  Command {i}: ERROR")
            elif status.busy:
                busy_count += 1
                print(f"  Command {i}: BUSY")
            else:
                print(f"  Command {i}: OK")

    print(f"\nResults:")
    print(f"  Errors: {error_count}")
    print(f"  Busy: {busy_count}")
    print(f"  Success: {10 - error_count - busy_count}")


def main():
    """Run all Milestone 4 demonstrations."""
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#  MILESTONE 4: DEVICE SIMULATION DEMONSTRATION" + " " * 22 + "#")
    print("#" + " " * 68 + "#")
    print("#  Virtual 1553 Bus with BC, RT, and BM devices" + " " * 21 + "#")
    print("#  No Hardware Required!" + " " * 46 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)

    try:
        demo_basic_communication()
        demo_bus_monitor()
        demo_broadcast()
        demo_mode_commands()
        demo_rt_handlers()
        demo_scheduled_communication()
        demo_error_conditions()

        print_section("MILESTONE 4 COMPLETE")
        print("\nAll device simulation components demonstrated successfully:")
        print("  ✓ Bus Controller (BC) - Master device")
        print("  ✓ Remote Terminal (RT) - Subsystem devices")
        print("  ✓ Bus Monitor (BM) - Passive observer")
        print("  ✓ Virtual Bus - Software simulation")
        print("  ✓ BC-to-RT transfers")
        print("  ✓ RT-to-BC transfers")
        print("  ✓ Broadcast messaging")
        print("  ✓ Mode commands")
        print("  ✓ Custom RT handlers")
        print("  ✓ Scheduled communication")
        print("  ✓ Error simulation")
        print("\nYou can now simulate complete 1553 networks in software!")
        print("=" * 70)

    except Exception as e:
        print(f"\n\nERROR during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
