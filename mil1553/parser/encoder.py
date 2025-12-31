"""
High-Level Message Encoder

This module provides a user-friendly API for encoding MIL-STD-1553B messages
to wire format with various encoding options and validation.
"""

from typing import Optional, Dict, Any
import logging

from mil1553.core.message import Message
from mil1553.core.validation import ProtocolValidator, ValidationResult
from mil1553.core.encoding import ManchesterEncoder, SimpleBinaryEncoder
from mil1553.core.exceptions import EncodingException


logger = logging.getLogger(__name__)


class MessageEncoder:
    """
    High-level encoder for MIL-STD-1553B messages.

    Provides encoding with optional validation, error handling, and
    configuration options.

    Example:
        >>> encoder = MessageEncoder(encoding="manchester", validate=True)
        >>> wire_data = encoder.encode(message)
    """

    def __init__(
        self,
        encoding: str = "binary",
        validate: bool = True,
        strict_validation: bool = True,
        raise_on_invalid: bool = False
    ):
        """
        Initialize encoder.

        Args:
            encoding: "manchester" or "binary"
            validate: If True, validate messages before encoding
            strict_validation: If True, use strict validation
            raise_on_invalid: If True, raise exception on invalid message
        """
        self.encoding = encoding.lower()
        self.validate = validate
        self.strict_validation = strict_validation
        self.raise_on_invalid = raise_on_invalid

        # Initialize validator if needed
        if self.validate:
            self.validator = ProtocolValidator(strict=strict_validation)
        else:
            self.validator = None

        # Select encoder
        if self.encoding == "manchester":
            self.encoder_class = ManchesterEncoder
        elif self.encoding == "binary":
            self.encoder_class = SimpleBinaryEncoder
        else:
            raise ValueError(f"Unknown encoding: {encoding}")

    def encode(
        self,
        message: Message,
        validate_override: Optional[bool] = None
    ) -> tuple[bytes, Optional[ValidationResult]]:
        """
        Encode a message to wire format.

        Args:
            message: Message to encode
            validate_override: Override default validation setting

        Returns:
            Tuple of (encoded_bytes, validation_result)
            validation_result is None if validation disabled

        Raises:
            EncodingException: If encoding fails
            ValidationException: If validation fails and raise_on_invalid=True

        Example:
            >>> encoder = MessageEncoder()
            >>> wire_data, result = encoder.encode(message)
            >>> if result and not result.is_valid:
            ...     print(f"Validation failed: {result}")
        """
        validation_result = None

        # Validate if requested
        should_validate = validate_override if validate_override is not None else self.validate

        if should_validate and self.validator:
            validation_result = self.validator.validate_message(message)

            if not validation_result.is_valid:
                logger.warning(f"Message validation failed: {validation_result}")

                if self.raise_on_invalid:
                    from mil1553.core.exceptions import ValidationException
                    raise ValidationException(
                        f"Message validation failed with {len(validation_result.violations)} violations"
                    )

        # Encode message
        try:
            encoded = message.to_wire_format(encoding=self.encoding)
            logger.debug(
                f"Encoded message: type={message.message_type.value}, "
                f"words={message.get_word_count()}, bytes={len(encoded)}"
            )
            return (encoded, validation_result)

        except Exception as e:
            logger.error(f"Encoding failed: {e}")
            raise EncodingException(f"Failed to encode message: {e}") from e

    def encode_batch(
        self,
        messages: list[Message]
    ) -> tuple[list[bytes], list[Optional[ValidationResult]]]:
        """
        Encode multiple messages.

        Args:
            messages: List of messages to encode

        Returns:
            Tuple of (encoded_messages, validation_results)

        Example:
            >>> encoder = MessageEncoder()
            >>> encoded_list, results = encoder.encode_batch([msg1, msg2, msg3])
        """
        encoded_messages = []
        validation_results = []

        for i, message in enumerate(messages):
            try:
                encoded, result = self.encode(message)
                encoded_messages.append(encoded)
                validation_results.append(result)
            except Exception as e:
                logger.error(f"Failed to encode message {i}: {e}")
                if self.raise_on_invalid:
                    raise
                # Continue with next message
                encoded_messages.append(b'')
                validation_results.append(None)

        return (encoded_messages, validation_results)

    def encode_to_stream(
        self,
        messages: list[Message],
        include_gaps: bool = False
    ) -> bytes:
        """
        Encode messages to a continuous stream.

        Args:
            messages: List of messages
            include_gaps: If True, include inter-message gaps (as null bytes)

        Returns:
            Continuous byte stream

        Example:
            >>> stream = encoder.encode_to_stream([msg1, msg2, msg3])
        """
        stream = bytearray()

        for i, message in enumerate(messages):
            encoded, _ = self.encode(message, validate_override=False)
            stream.extend(encoded)

            # Add gap if requested and not last message
            if include_gaps and i < len(messages) - 1:
                # Calculate gap bytes (simplified - just add padding)
                gap_time = message.gap_time if message.gap_time else 0
                # Convert gap time to bytes (rough approximation)
                gap_bytes = int(gap_time / 8)  # Assuming 8 μs per byte
                stream.extend(b'\x00' * gap_bytes)

        return bytes(stream)

    def get_stats(self, message: Message) -> Dict[str, Any]:
        """
        Get encoding statistics for a message.

        Args:
            message: Message to analyze

        Returns:
            Dictionary with statistics

        Example:
            >>> stats = encoder.get_stats(message)
            >>> print(f"Encoded size: {stats['encoded_bytes']} bytes")
        """
        encoded, result = self.encode(message, validate_override=False)

        stats = {
            'message_type': message.message_type.value,
            'total_words': message.get_word_count(),
            'command_words': len(message.command_words),
            'status_words': len(message.status_words),
            'data_words': len(message.data_words),
            'encoded_bytes': len(encoded),
            'encoding': self.encoding,
            'duration_us': message.calculate_message_duration(),
            'is_valid': result.is_valid if result else None,
            'violations': len(result.violations) if result else 0,
            'warnings': len(result.warnings) if result else 0,
        }

        return stats


class StreamEncoder:
    """
    Encoder for continuous message streams.

    Maintains state for encoding sequences of messages with
    proper timing and gaps.
    """

    def __init__(self, encoding: str = "binary"):
        """
        Initialize stream encoder.

        Args:
            encoding: "manchester" or "binary"
        """
        self.encoder = MessageEncoder(encoding=encoding, validate=False)
        self.stream = bytearray()
        self.message_count = 0
        self.total_bytes = 0

    def add_message(self, message: Message):
        """
        Add a message to the stream.

        Args:
            message: Message to add
        """
        encoded, _ = self.encoder.encode(message)
        self.stream.extend(encoded)
        self.message_count += 1
        self.total_bytes += len(encoded)

    def get_stream(self) -> bytes:
        """Get the encoded stream."""
        return bytes(self.stream)

    def reset(self):
        """Reset the stream."""
        self.stream = bytearray()
        self.message_count = 0
        self.total_bytes = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get stream statistics."""
        return {
            'message_count': self.message_count,
            'total_bytes': self.total_bytes,
            'average_bytes_per_message': self.total_bytes / self.message_count if self.message_count > 0 else 0
        }
