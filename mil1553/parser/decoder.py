"""
High-Level Message Decoder

This module provides a user-friendly API for decoding MIL-STD-1553B messages
from wire format with various decoding options and validation.
"""

from typing import Optional, List, Tuple
import logging

from mil1553.core.message import Message, MessageType
from mil1553.core.validation import ProtocolValidator, ValidationResult
from mil1553.core.encoding import ManchesterEncoder, SimpleBinaryEncoder
from mil1553.core.exceptions import DecodingException
from mil1553.core.constants import TOTAL_WORD_BITS


logger = logging.getLogger(__name__)


class MessageDecoder:
    """
    High-level decoder for MIL-STD-1553B messages.

    Provides decoding with optional validation, error handling, and
    configuration options.

    Example:
        >>> decoder = MessageDecoder(encoding="manchester", validate=True)
        >>> message = decoder.decode(wire_data, MessageType.BC_TO_RT)
    """

    def __init__(
        self,
        encoding: str = "binary",
        validate: bool = True,
        strict_validation: bool = True,
        raise_on_invalid: bool = False
    ):
        """
        Initialize decoder.

        Args:
            encoding: "manchester" or "binary"
            validate: If True, validate decoded messages
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

        # Select decoder
        if self.encoding == "manchester":
            self.decoder_class = ManchesterEncoder
        elif self.encoding == "binary":
            self.decoder_class = SimpleBinaryEncoder
        else:
            raise ValueError(f"Unknown encoding: {encoding}")

    def decode(
        self,
        data: bytes,
        message_type: MessageType,
        timestamp: Optional[float] = None,
        validate_override: Optional[bool] = None
    ) -> Tuple[Message, Optional[ValidationResult]]:
        """
        Decode a message from wire format.

        Args:
            data: Encoded bytes
            message_type: Expected message type
            timestamp: Optional timestamp
            validate_override: Override default validation setting

        Returns:
            Tuple of (decoded_message, validation_result)
            validation_result is None if validation disabled

        Raises:
            DecodingException: If decoding fails
            ValidationException: If validation fails and raise_on_invalid=True

        Example:
            >>> decoder = MessageDecoder()
            >>> message, result = decoder.decode(wire_data, MessageType.BC_TO_RT)
            >>> if result and not result.is_valid:
            ...     print(f"Validation failed: {result}")
        """
        validation_result = None

        # Decode message
        try:
            message = Message.from_wire_format(
                data=data,
                message_type=message_type,
                encoding=self.encoding,
                timestamp=timestamp
            )
            logger.debug(
                f"Decoded message: type={message.message_type.value}, "
                f"words={message.get_word_count()}"
            )

        except Exception as e:
            logger.error(f"Decoding failed: {e}")
            raise DecodingException(f"Failed to decode message: {e}") from e

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

        return (message, validation_result)

    def decode_batch(
        self,
        data_list: List[Tuple[bytes, MessageType]],
        timestamps: Optional[List[float]] = None
    ) -> Tuple[List[Message], List[Optional[ValidationResult]]]:
        """
        Decode multiple messages.

        Args:
            data_list: List of (data, message_type) tuples
            timestamps: Optional list of timestamps

        Returns:
            Tuple of (decoded_messages, validation_results)

        Example:
            >>> decoder = MessageDecoder()
            >>> data_list = [(data1, MessageType.BC_TO_RT), (data2, MessageType.RT_TO_BC)]
            >>> messages, results = decoder.decode_batch(data_list)
        """
        messages = []
        validation_results = []

        for i, (data, msg_type) in enumerate(data_list):
            timestamp = timestamps[i] if timestamps and i < len(timestamps) else None

            try:
                message, result = self.decode(data, msg_type, timestamp)
                messages.append(message)
                validation_results.append(result)
            except Exception as e:
                logger.error(f"Failed to decode message {i}: {e}")
                if self.raise_on_invalid:
                    raise
                # Continue with next message
                messages.append(None)
                validation_results.append(None)

        return (messages, validation_results)

    def decode_stream(
        self,
        stream: bytes,
        word_size_bytes: int = 3
    ) -> List[Message]:
        """
        Decode messages from a continuous stream.

        This is a simplified implementation that assumes messages are
        back-to-back without gaps.

        Args:
            stream: Continuous byte stream
            word_size_bytes: Bytes per word (3 for binary, 20 for Manchester)

        Returns:
            List of decoded messages

        Note:
            This is a basic implementation. For production use, consider
            implementing sync detection and message boundary detection.

        Example:
            >>> messages = decoder.decode_stream(stream_data)
        """
        if self.encoding == "manchester":
            word_size_bytes = TOTAL_WORD_BITS

        messages = []
        offset = 0

        while offset < len(stream):
            # Try to decode a message
            # This is simplified - real implementation would need to detect
            # message boundaries and types

            # For now, assume minimum message size (command + 1 data word)
            min_size = word_size_bytes * 2

            if offset + min_size > len(stream):
                break

            # Extract potential message data
            # In real implementation, would detect sync and parse structure
            message_data = stream[offset:offset + min_size]

            try:
                # Try to decode as BC-to-RT (most common)
                message, _ = self.decode(message_data, MessageType.BC_TO_RT, validate_override=False)
                messages.append(message)
                offset += min_size

            except Exception as e:
                logger.debug(f"Failed to decode at offset {offset}: {e}")
                # Skip to next potential message
                offset += word_size_bytes

        return messages


class StreamDecoder:
    """
    Decoder for continuous message streams with state management.

    Maintains decoding state and provides buffering for partial messages.
    """

    def __init__(self, encoding: str = "binary"):
        """
        Initialize stream decoder.

        Args:
            encoding: "manchester" or "binary"
        """
        self.decoder = MessageDecoder(encoding=encoding, validate=False)
        self.buffer = bytearray()
        self.messages = []
        self.encoding = encoding

    def add_data(self, data: bytes):
        """
        Add data to the buffer.

        Args:
            data: Raw bytes to add
        """
        self.buffer.extend(data)
        self._try_decode()

    def _try_decode(self):
        """Attempt to decode messages from buffer."""
        word_size = 3 if self.encoding == "binary" else TOTAL_WORD_BITS
        min_message_size = word_size * 2  # At least command + 1 word

        while len(self.buffer) >= min_message_size:
            try:
                # Try to decode a message
                message_data = bytes(self.buffer[:min_message_size])
                message, _ = self.decoder.decode(message_data, MessageType.BC_TO_RT, validate_override=False)

                self.messages.append(message)

                # Remove decoded data from buffer
                del self.buffer[:min_message_size]

            except Exception:
                # Can't decode, wait for more data or skip this byte
                del self.buffer[0]

    def get_messages(self, clear: bool = True) -> List[Message]:
        """
        Get decoded messages.

        Args:
            clear: If True, clear the message list after returning

        Returns:
            List of decoded messages
        """
        messages = self.messages[:]
        if clear:
            self.messages = []
        return messages

    def reset(self):
        """Reset the decoder state."""
        self.buffer = bytearray()
        self.messages = []
