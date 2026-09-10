"""Lightweight, inference-only adapter for the committed URL CNN."""

import json
from pathlib import Path

import h5py
import numpy as np


class ModelLoadError(RuntimeError):
    """Raised when model artifacts do not match the supported architecture."""


class URLCNNClassifier:
    """Run the trained Keras CNN with NumPy instead of a TensorFlow runtime."""

    _EMBEDDING_PATH = (
        "model_weights/embedding_1/sequential_1/embedding_1/embeddings"
    )
    _CONV_KERNEL_PATH = "model_weights/conv1d_1/sequential_1/conv1d_1/kernel"
    _CONV_BIAS_PATH = "model_weights/conv1d_1/sequential_1/conv1d_1/bias"
    _DENSE_KERNEL_PATH = "model_weights/dense_1/sequential_1/dense_1/kernel"
    _DENSE_BIAS_PATH = "model_weights/dense_1/sequential_1/dense_1/bias"

    def __init__(self, model_path: Path, tokenizer_path: Path):
        self.model_path = Path(model_path)
        self.tokenizer_path = Path(tokenizer_path)
        self._load_tokenizer()
        self._load_weights()
        self._validate_artifacts()

    def _load_tokenizer(self) -> None:
        try:
            config = json.loads(self.tokenizer_path.read_text(encoding="utf-8"))
            self.max_length = int(config["max_length"])
            self.lower = bool(config["lower"])
            self.char_index = {
                str(character): int(index)
                for character, index in config["char_index"].items()
            }
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ModelLoadError("The tokenizer metadata is invalid.") from exc

        if config.get("format_version") != 1:
            raise ModelLoadError("The tokenizer format version is unsupported.")
        if config.get("padding") != "post" or config.get("truncating") != "post":
            raise ModelLoadError("Only the model's post-padding format is supported.")

    def _load_weights(self) -> None:
        try:
            with h5py.File(self.model_path, "r") as model_file:
                self.embedding = np.asarray(
                    model_file[self._EMBEDDING_PATH],
                    dtype=np.float32,
                )
                self.conv_kernel = np.asarray(
                    model_file[self._CONV_KERNEL_PATH],
                    dtype=np.float32,
                )
                self.conv_bias = np.asarray(
                    model_file[self._CONV_BIAS_PATH],
                    dtype=np.float32,
                )
                self.dense_kernel = np.asarray(
                    model_file[self._DENSE_KERNEL_PATH],
                    dtype=np.float32,
                )
                self.dense_bias = np.asarray(
                    model_file[self._DENSE_BIAS_PATH],
                    dtype=np.float32,
                )
        except (OSError, KeyError, ValueError) as exc:
            raise ModelLoadError("The CNN model artifact is invalid.") from exc

    def _validate_artifacts(self) -> None:
        expected_shapes = {
            "embedding": (1000, 50),
            "conv_kernel": (5, 50, 128),
            "conv_bias": (128,),
            "dense_kernel": (128, 1),
            "dense_bias": (1,),
        }
        for name, expected_shape in expected_shapes.items():
            actual_shape = getattr(self, name).shape
            if actual_shape != expected_shape:
                raise ModelLoadError(
                    f"Unexpected {name} shape: {actual_shape}; expected {expected_shape}."
                )

        if self.max_length < self.conv_kernel.shape[0]:
            raise ModelLoadError("The tokenizer sequence length is too short.")
        if max(self.char_index.values(), default=0) >= self.embedding.shape[0]:
            raise ModelLoadError("The tokenizer vocabulary exceeds the embedding table.")

    def _encode(self, url: str) -> np.ndarray:
        text = url.replace("https://", "").replace("http://", "").replace("www.", "")
        text = text.lower() if self.lower else text
        sequence = [self.char_index[character] for character in text if character in self.char_index]
        sequence = sequence[: self.max_length]
        encoded = np.zeros(self.max_length, dtype=np.int64)
        if sequence:
            encoded[: len(sequence)] = sequence
        return encoded

    def predict_probability(self, url: str) -> float:
        """Return the trained model's phishing probability in the range 0..1."""
        embedded = self.embedding[self._encode(url)]
        kernel_size = self.conv_kernel.shape[0]
        output_length = self.max_length - kernel_size + 1
        convolution = np.broadcast_to(
            self.conv_bias,
            (output_length, self.conv_bias.shape[0]),
        ).copy()

        for offset in range(kernel_size):
            convolution += (
                embedded[offset : offset + output_length] @ self.conv_kernel[offset]
            )

        pooled = np.maximum(convolution, 0).max(axis=0)
        logit = float((pooled @ self.dense_kernel).item() + self.dense_bias.item())
        probability = 1.0 / (1.0 + np.exp(-np.clip(logit, -80.0, 80.0)))
        return float(probability)
