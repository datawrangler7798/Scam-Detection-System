# pipeline/scam_detector/parser.py

from typing import Dict, Any
from LLM.validator import validate_output
from utils import get_logger, extract_json_from_text

logger = get_logger(__name__)

class OutputParser:
    """Parses LLM output into structured format."""
    
    def parse_llm_output(self, llm_output: str) -> Dict[str, Any]:
        """
        Extract and parse JSON structure from LLM response.
        
        Args:
            llm_output: Raw text output from the LLM
            
        Returns:
            Dictionary containing structured detection results with keys:
            - label: str - Classification result ("Scam", "Not Scam", "Uncertain")
            - reasoning: str - Step-by-step analysis
            - intent: str - Description of user intent
            - risk_factors: List[str] - List of identified red flags
            
        Note:
            If parsing fails, returns a fallback dictionary with "Uncertain" label
            and error information in the reasoning field.
        """
        logger.info(f"Parsing LLM output of length: {len(llm_output)}")
        
        # Try to extract JSON using utils function
        parsed_json = extract_json_from_text(llm_output)
        
        if not parsed_json:
            return self._fallback("No JSON found")

        try:
            # Do not trust a syntactically valid JSON response until its complete
            # Gemini output has passed the Pydantic contract.
            validated_response = validate_output(parsed_json)
            logger.info("Successfully parsed and validated LLM output.")
            return validated_response.model_dump()
        except ValueError as error:
            logger.warning("Gemini response failed schema validation: %s", error)
            return self._fallback(f"Schema validation failed: {error}")

    @staticmethod
    def _fallback(error: str) -> Dict[str, Any]:
        """Return a safe, schema-compliant result for invalid model output."""
        logger.warning("Invalid Gemini response: %s", error)
        return {
            "label": "Uncertain",
            "reasoning": f"Failed to process response: {error}",
            "intent": "Could not determine",
            "risk_factors": [],
        }
