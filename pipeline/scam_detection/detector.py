# pipeline/scam_detector/detector.py

from typing import List, Dict, Any
from uuid import uuid4
from .builder import build_prompt
from .executor import LLMExecutor
from .parser import OutputParser
from utils import get_logger, log_audit_event

logger = get_logger(__name__)

class ScamDetector:
    """Orchestrates the scam detection pipeline."""

    def __init__(self, strategy: str = "react") -> None:
        """Initializes the pipeline components."""
        self.executor = LLMExecutor()
        self.parser = OutputParser()
        self.strategy = strategy
        logger.info(f"Initialized ScamDetector with strategy: {self.strategy}")

    def detect(self, message: str) -> Dict[str, Any]:
        """Runs scam detection on a single message."""
        request_id = str(uuid4())
        model_name = self.executor.llm.model_name
        logger.info(f"Starting detection for message length: {len(message)}")
        log_audit_event(
            "scan_started",
            request_id=request_id,
            strategy=self.strategy,
            model=model_name,
            user_input=message,
        )
        try:
            # The 3-step pipeline
            prompt = build_prompt(message, self.strategy)
            log_audit_event(
                "model_request",
                request_id=request_id,
                model=model_name,
                prompt=prompt,
            )
            raw_response = self.executor.execute(prompt)
            log_audit_event(
                "model_response",
                request_id=request_id,
                model=model_name,
                raw_model_output=raw_response,
            )
            parsed_result = self.parser.parse_llm_output(raw_response)
            log_audit_event(
                "scan_completed",
                request_id=request_id,
                model=model_name,
                parsed_output=parsed_result,
            )

            logger.info(f"Detection successful. Result: {parsed_result.get('label', 'Unknown')}")
            return parsed_result

        except Exception as e:
            logger.error(f"Detection pipeline failed: {e}")
            log_audit_event(
                "scan_failed",
                request_id=request_id,
                model=model_name,
                error=str(e),
            )
            # Re-raise the exception to be handled by the caller (UI layer)
            raise

    def detect_batch(self, messages: List[str]) -> List[Dict[str, Any]]:
        """Runs scam detection on a list of messages."""
        total_messages = len(messages)
        logger.info(f"Starting batch detection for {total_messages} messages.")
        
        results: List[Dict[str, Any]] = []
        
        for i, message in enumerate(messages):
            try:
                result = self.detect(message)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to process message {i+1}/{total_messages}: {e}")
                # Append a fallback error result for the failed message
                error_result = {
                    "label": "Uncertain",
                    "reasoning": f"Error processing message: {e}",
                    "intent": "Could not determine",
                    "risk_factors": ["processing_error"]
                }
                results.append(error_result)
        
        successful = sum(1 for r in results if r.get("label") != "Uncertain" or "processing_error" not in r.get("risk_factors", []))
        logger.info(f"Batch processing complete. {successful}/{total_messages} succeeded.")
        return results
