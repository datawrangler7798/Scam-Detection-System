"""Lightweight evaluation metrics for scam-detection predictions."""

from collections.abc import Sequence
from typing import Any


def evaluate_model(
    actual_labels: Sequence[Any], predicted_labels: Sequence[Any]
) -> dict[str, Any]:
    """Calculate accuracy metrics for equally sized label sequences.

    Labels are compared as trimmed, case-insensitive strings so dataset values
    such as ``scam`` and model values such as ``Scam`` are treated equally.
    """
    if len(actual_labels) != len(predicted_labels):
        raise ValueError(
            "actual_labels and predicted_labels must contain the same number of items"
        )

    total_predictions = len(actual_labels)
    correct_predictions = sum(
        str(actual).strip().casefold() == str(predicted).strip().casefold()
        for actual, predicted in zip(actual_labels, predicted_labels)
    )
    overall_accuracy = (
        round((correct_predictions / total_predictions) * 100, 2)
        if total_predictions
        else 0.0
    )

    return {
        "overall_accuracy": overall_accuracy,
        "total_predictions": total_predictions,
        "correct_predictions": correct_predictions,
        "summary": (
            f"{correct_predictions} of {total_predictions} predictions were correct "
            f"({overall_accuracy}%)."
        ),
    }
