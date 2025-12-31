"""
Fuzzing Engine for MIL-STD-1553B Security Testing

This module provides comprehensive fuzzing capabilities for testing
1553B implementations against malformed and edge-case inputs.
"""

from typing import List, Optional, Callable, Dict, Any
from abc import ABC, abstractmethod
import random

from mil1553.core.word import Word, CommandWord, StatusWord, DataWord
from mil1553.core.message import Message
from mil1553.core.constants import (
    MAX_RT_ADDRESS, MAX_SUBADDRESS, MAX_WORD_COUNT,
    BROADCAST_ADDRESS, SyncPattern
)
from mil1553.core.exceptions import FuzzingException
from mil1553.utils.bitops import flip_bit, set_bits


class FuzzingStrategy(ABC):
    """
    Abstract base class for fuzzing strategies.

    Each strategy implements a different approach to generating
    test cases from a template message or word.
    """

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize fuzzing strategy.

        Args:
            seed: Random seed for reproducibility
        """
        self.seed = seed
        if seed is not None:
            random.seed(seed)

    @abstractmethod
    def fuzz_word(self, word: Word) -> Word:
        """
        Fuzz a single word.

        Args:
            word: Word to fuzz

        Returns:
            Fuzzed word
        """
        pass

    @abstractmethod
    def fuzz_message(self, message: Message) -> Message:
        """
        Fuzz a complete message.

        Args:
            message: Message to fuzz

        Returns:
            Fuzzed message
        """
        pass

    def generate_mutations(self, target: Any, count: int) -> List[Any]:
        """
        Generate multiple mutations of a target.

        Args:
            target: Word or Message to mutate
            count: Number of mutations to generate

        Returns:
            List of mutated copies
        """
        mutations = []
        for _ in range(count):
            if isinstance(target, Word):
                mutations.append(self.fuzz_word(target))
            elif isinstance(target, Message):
                mutations.append(self.fuzz_message(target))
        return mutations


class BitFlipFuzzer(FuzzingStrategy):
    """
    Bit-flip fuzzing strategy.

    Randomly flips bits in words to create malformed packets.
    """

    def __init__(self, mutation_rate: float = 0.05, seed: Optional[int] = None):
        """
        Initialize bit-flip fuzzer.

        Args:
            mutation_rate: Probability of flipping each bit (0.0-1.0)
            seed: Random seed
        """
        super().__init__(seed)
        self.mutation_rate = mutation_rate

    def fuzz_word(self, word: Word) -> Word:
        """Fuzz word by randomly flipping bits."""
        # Create copy
        fuzzed = word.__class__.__new__(word.__class__)
        fuzzed.__dict__.update(word.__dict__)

        # Flip random bits in the 20-bit word
        raw_value = fuzzed.raw_value
        for bit_pos in range(20):
            if random.random() < self.mutation_rate:
                raw_value = flip_bit(raw_value, bit_pos)

        # Reconstruct word from fuzzed raw value
        sync = (raw_value >> 17) & 0x7
        data = (raw_value >> 1) & 0xFFFF
        parity = raw_value & 0x1

        return word.__class__._from_parts(sync, data, parity, word.timestamp)

    def fuzz_message(self, message: Message) -> Message:
        """Fuzz message by bit-flipping random words."""
        # Create copy
        import copy
        fuzzed = copy.deepcopy(message)

        # Fuzz random words
        all_words = (fuzzed.command_words + fuzzed.status_words + fuzzed.data_words)

        for word in all_words:
            if random.random() < self.mutation_rate:
                # Fuzz this word (in-place modification of copied word)
                fuzzed_word = self.fuzz_word(word)
                # Update word attributes
                word.__dict__.update(fuzzed_word.__dict__)

        return fuzzed


class BoundaryFuzzer(FuzzingStrategy):
    """
    Boundary value fuzzing strategy.

    Tests edge cases and boundary values for all fields.
    """

    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)

        # Define boundary values for each field
        self.boundaries = {
            'rt_address': [0, 1, 15, 30, 31, 32, 255],  # Include invalid
            'subaddress': [0, 1, 15, 30, 31, 32, 255],
            'word_count': [0, 1, 15, 31, 32, 255],
            'data': [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF],
            'sync': [0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111]
        }

    def fuzz_word(self, word: Word) -> Word:
        """Fuzz word with boundary values, bypassing validation for testing."""
        if isinstance(word, CommandWord):
            # Construct data field directly with potentially invalid values
            rt_addr = random.choice(self.boundaries['rt_address'])
            tr = random.randint(0, 1)
            subaddr = random.choice(self.boundaries['subaddress'])
            wc = random.choice(self.boundaries['word_count'])

            # Pack into 16-bit data field
            data = ((rt_addr & 0xFF) << 11) | ((tr & 0x1) << 10) | ((subaddr & 0xFF) << 5) | (wc & 0xFF)
            sync = random.choice([0b000, 0b100])  # COMMAND_STATUS usually 0b100
            parity = random.randint(0, 1)

            return word.__class__._from_parts(sync, data, parity, word.timestamp)

        elif isinstance(word, StatusWord):
            # Construct status with potentially invalid RT address
            rt_addr = random.choice(self.boundaries['rt_address'])
            # Random status bits
            status_bits = random.randint(0, 0x3FF)  # 10 bits

            data = ((rt_addr & 0xFF) << 11) | (status_bits & 0x7FF)
            sync = random.choice([0b000, 0b100])  # COMMAND_STATUS usually 0b100
            parity = random.randint(0, 1)

            return word.__class__._from_parts(sync, data, parity, word.timestamp)

        elif isinstance(word, DataWord):
            payload = random.choice(self.boundaries['data'])
            sync = random.choice([0b000, 0b100])  # DATA usually 0b000
            parity = random.randint(0, 1)

            return word.__class__._from_parts(sync, payload, parity, word.timestamp)
        else:
            return word

    def fuzz_message(self, message: Message) -> Message:
        """Fuzz message with boundary values."""
        import copy
        fuzzed = copy.deepcopy(message)

        # Fuzz each word
        fuzzed.command_words = [self.fuzz_word(w) for w in fuzzed.command_words]
        fuzzed.status_words = [self.fuzz_word(w) for w in fuzzed.status_words]
        fuzzed.data_words = [self.fuzz_word(w) for w in fuzzed.data_words]

        return fuzzed


class SemanticFuzzer(FuzzingStrategy):
    """
    Semantic fuzzing strategy.

    Maintains protocol structure but fuzzes semantic meaning
    (e.g., word count mismatch, reserved bits set).
    """

    def fuzz_word(self, word: Word) -> Word:
        """Fuzz word semantically."""
        import copy
        fuzzed = copy.deepcopy(word)

        if isinstance(word, CommandWord):
            # Create semantic violations
            mutation_type = random.choice([
                'word_count_mismatch',
                'invalid_mode_code',
                'reserved_bits'
            ])

            if mutation_type == 'word_count_mismatch':
                # Word count won't match actual data
                fuzzed.word_count_mode = random.randint(0, 31)

        elif isinstance(word, StatusWord):
            # Set reserved bits (should be zero per spec)
            fuzzed.reserved = random.randint(1, 7)  # Non-zero

        return fuzzed

    def fuzz_message(self, message: Message) -> Message:
        """Fuzz message semantically."""
        import copy
        fuzzed = copy.deepcopy(message)

        # Create semantic violations
        violation_type = random.choice([
            'word_count_mismatch',
            'address_mismatch',
            'extra_words',
            'missing_words'
        ])

        if violation_type == 'word_count_mismatch':
            # Declared word count != actual count
            if fuzzed.command_words:
                fuzzed.command_words[0].word_count_mode = random.randint(1, 10)
                # But keep actual data_words as is

        elif violation_type == 'address_mismatch':
            # Status word RT address != command word RT address
            if fuzzed.command_words and fuzzed.status_words:
                fuzzed.status_words[0].rt_address = (fuzzed.command_words[0].rt_address + 1) % 32

        elif violation_type == 'extra_words':
            # Add extra data word
            fuzzed.data_words.append(DataWord(payload=0xEEEE))

        elif violation_type == 'missing_words':
            # Remove data word if any
            if fuzzed.data_words:
                fuzzed.data_words.pop()

        return fuzzed


class Fuzzer:
    """
    Main fuzzing engine.

    Orchestrates fuzzing strategies and test case generation.
    """

    def __init__(
        self,
        strategy: Optional[FuzzingStrategy] = None,
        seed: Optional[int] = None
    ):
        """
        Initialize fuzzer.

        Args:
            strategy: Fuzzing strategy to use (defaults to BitFlipFuzzer)
            seed: Random seed for reproducibility
        """
        self.strategy = strategy or BitFlipFuzzer(seed=seed)
        self.seed = seed
        self.test_cases_generated = 0

    def fuzz_word(self, word: Word) -> Word:
        """
        Fuzz a single word.

        Args:
            word: Word to fuzz

        Returns:
            Fuzzed word
        """
        return self.strategy.fuzz_word(word)

    def fuzz_message(self, message: Message) -> Message:
        """
        Fuzz a complete message.

        Args:
            message: Message to fuzz

        Returns:
            Fuzzed message
        """
        return self.strategy.fuzz_message(message)

    def generate_test_cases(
        self,
        template: Message,
        count: int = 100
    ) -> List[Message]:
        """
        Generate multiple fuzzed test cases from a template.

        Args:
            template: Template message to fuzz
            count: Number of test cases to generate

        Returns:
            List of fuzzed messages

        Example:
            >>> fuzzer = Fuzzer(strategy=BitFlipFuzzer(mutation_rate=0.1))
            >>> template = create_bc_to_rt_message(5, 10, [DataWord(payload=0x1234)])
            >>> test_cases = fuzzer.generate_test_cases(template, count=1000)
        """
        test_cases = []

        for i in range(count):
            fuzzed = self.fuzz_message(template)
            test_cases.append(fuzzed)
            self.test_cases_generated += 1

        return test_cases

    def generate_diverse_test_cases(
        self,
        template: Message,
        count: int = 100
    ) -> List[Message]:
        """
        Generate diverse test cases using multiple strategies.

        Args:
            template: Template message
            count: Number of test cases

        Returns:
            List of fuzzed messages using different strategies
        """
        strategies = [
            BitFlipFuzzer(mutation_rate=0.05, seed=self.seed),
            BitFlipFuzzer(mutation_rate=0.10, seed=self.seed),
            BoundaryFuzzer(seed=self.seed),
            SemanticFuzzer(seed=self.seed)
        ]

        test_cases = []
        cases_per_strategy = count // len(strategies)

        for strategy in strategies:
            old_strategy = self.strategy
            self.strategy = strategy

            for _ in range(cases_per_strategy):
                test_cases.append(self.fuzz_message(template))

            self.strategy = old_strategy

        # Fill remaining with current strategy
        while len(test_cases) < count:
            test_cases.append(self.fuzz_message(template))

        return test_cases

    def fuzz_field(
        self,
        word: Word,
        field: str,
        values: List[Any]
    ) -> List[Word]:
        """
        Fuzz a specific field with given values.

        Args:
            word: Word to fuzz
            field: Field name to fuzz
            values: List of values to try

        Returns:
            List of fuzzed words

        Example:
            >>> cmd = CommandWord(rt_address=5, ...)
            >>> fuzzed = fuzzer.fuzz_field(cmd, 'rt_address', [0, 31, 32, 255])
        """
        import copy
        fuzzed_words = []

        for value in values:
            fuzzed = copy.deepcopy(word)
            if hasattr(fuzzed, field):
                setattr(fuzzed, field, value)
                # Recalculate internal state if needed
                if isinstance(fuzzed, CommandWord):
                    # Rebuild data field
                    data = (
                        (fuzzed.rt_address << 11) |
                        (fuzzed.transmit_receive << 10) |
                        (fuzzed.subaddress << 5) |
                        fuzzed.word_count_mode
                    )
                    fuzzed.data = data
                    fuzzed._update_raw_value()
                fuzzed_words.append(fuzzed)

        return fuzzed_words

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzing statistics."""
        return {
            'test_cases_generated': self.test_cases_generated,
            'strategy': self.strategy.__class__.__name__,
            'seed': self.seed
        }


class MutationFuzzer:
    """
    Advanced mutation-based fuzzer with mutation tracking.
    """

    def __init__(self):
        self.mutations_applied = []

    def add_mutation(self, mutation: Callable):
        """Add a mutation function."""
        self.mutations_applied.append(mutation)

    def apply_mutations(self, target: Word) -> List[Word]:
        """Apply all mutations to target."""
        mutated = []

        for mutation in self.mutations_applied:
            try:
                result = mutation(target)
                mutated.append(result)
            except Exception as e:
                # Mutation failed, skip
                pass

        return mutated


# Pre-defined mutation functions
def mutate_parity(word: Word) -> Word:
    """Flip parity bit."""
    return word.corrupt_parity()


def mutate_sync(word: Word) -> Word:
    """Corrupt sync pattern."""
    return word.corrupt_sync()


def mutate_address_overflow(word: CommandWord) -> CommandWord:
    """Set address to invalid value."""
    import copy
    fuzzed = copy.deepcopy(word)
    fuzzed.rt_address = 255  # Out of range
    return fuzzed
