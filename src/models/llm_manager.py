"""Advanced LLM Manager with LangChain integration and probability support."""

import logging
import json
import time
import configparser
import os
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass

# LangChain imports
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import BaseOutputParser, JsonOutputParser
from langchain_core.exceptions import OutputParserException
from typing import List
try:
    from pydantic import BaseModel, Field
except ImportError:
    # Fallback for older pydantic versions
    from pydantic.v1 import BaseModel, Field

# Model-specific imports
import google.generativeai as genai
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch
from peft import PeftModel

from utils.database import Database
from utils.logger import setup_logger

logger = logging.getLogger(__name__)

class CWERankingOutput(BaseModel):
    """Structured output model for CWE rankings."""
    cwe_list: List[str] = Field(
        description="List of exactly 5 CWE identifiers in format CWE-XXX, ordered by likelihood",
        min_items=5,
        max_items=5
    )

@dataclass
class LLMResponse:
    """Data class for LLM responses with probability information."""
    content: str
    probability: Optional[float] = None
    raw_response: Optional[str] = None
    

def _llm_temperature() -> float:
    """Sampling temperature for LLM generation. Set via LLMKB_TEMPERATURE env (default 0)."""
    try:
        return float(os.environ.get("LLMKB_TEMPERATURE", "0"))
    except (TypeError, ValueError):
        return 0.0


def _sampling_kwargs(temp: float) -> dict:
    """Return HF generate/pipeline sampling kwargs. T<=0 -> greedy; T>0 -> sampling."""
    if temp <= 0:
        return {"do_sample": False}
    return {"do_sample": True, "temperature": temp}

class VulnerabilityOutputParser(BaseOutputParser[int]):
    """LangChain output parser for vulnerability detection responses."""
    
    def parse(self, text: str) -> int:
        """Parse the LLM output to extract vulnerability status.
        
        Args:
            text: Raw LLM output text
            
        Returns:
            1 if vulnerable, 0 if not vulnerable, -1 if not sure
            
        Raises:
            OutputParserException: If parsing fails
        """
        import re
        
        original_text = text
        text = text.strip().lower()
        
        # Direct numeric responses
        if text in ['1', '0']:
            return int(text)
        
        # ONLY return -1 for VERY EXPLICIT "not sure" statements (highly restrictive)
        # Must be very clear and unambiguous uncertainty without any leaning
        explicit_not_sure = [
            'impossible to say', 'insufficient information', 
            'need more context', 'need more information',
            'unable to determine', 'unable to tell'
        ]
        
        # Special case: "cannot determine" but with context (e.g., "without more context")
        # If followed by qualifier, often means they need more info, true -1
        # If standalone, may still have clues in the text
        has_cannot_determine = 'cannot determine' in text or 'cannot tell' in text
        has_qualifier = any(q in text for q in ['without', 'need more', 'require more', 'requires more'])
        
        # Only treat as explicit unsure if it has the qualifier AND text is short (main message)
        has_explicit_unsure = any(indicator in text for indicator in explicit_not_sure)
        if has_cannot_determine and has_qualifier and len(text.split()) < 15:
            has_explicit_unsure = True
        
        # Expanded NEGATIVE indicators (not vulnerable = 0)
        # Use word boundaries for short words to avoid false matches
        negative_indicators = [
            ' no ', ' no.', ' no,', 'not vulnerable', 'no vulnerability', 'secure', 'safe',
            'no security issue', 'no security flaw', 'no security problem',
            'not a vulnerability', 'does not contain', 'does not have',
            'appears safe', 'seems safe', 'looks safe', 'likely safe',
            'probably safe', 'likely not vulnerable', 'probably not vulnerable',
            'unlikely to be vulnerable', 'no obvious vulnerability',
            'no apparent vulnerability', 'no clear vulnerability',
            'does not appear vulnerable', 'doesn\'t appear vulnerable',
            'does not seem vulnerable', 'doesn\'t seem vulnerable',
            'not seem problematic', 'doesn\'t seem problematic', 'not problematic',
            'no risk', 'low risk', 'minimal risk', 'not risky',
            'protected', 'defended', 'sanitized', 'validated',
            'properly checked', 'properly handled', 'proper validation'
        ]
        
        # Expanded POSITIVE indicators (vulnerable = 1)
        positive_indicators = [
            'yes', 'vulnerable', 'has vulnerability', 'contains vulnerability',
            'security issue', 'security flaw', 'security problem', 'security risk',
            'has a vulnerability', 'is vulnerable', 'appears vulnerable',
            'vulnerability found', 'vulnerability detected', 'vulnerability present',
            'seems vulnerable', 'looks vulnerable', 'likely vulnerable',
            'probably vulnerable', 'potentially vulnerable', 'possibly vulnerable',
            'could be vulnerable', 'may be vulnerable', 'might be vulnerable',
            'at risk', 'high risk', 'risky', 'unsafe', 'insecure',
            'exploitable', 'can be exploited', 'potential exploit',
            'buffer overflow', 'sql injection', 'xss', 'injection',
            'use after free', 'memory leak', 'race condition',
            'unchecked', 'unvalidated', 'unsanitized', 'improper',
            'lack of validation', 'missing check', 'no validation',
            'security concern', 'concerning', 'problematic'
        ]
        
        # Count positive and negative indicators
        positive_count = sum(1 for indicator in positive_indicators if indicator in text)
        negative_count = sum(1 for indicator in negative_indicators if indicator in text)
        
        # Special handling for "leans" or "but" phrases - extract the direction
        if 'leans' in text or 'but ' in text:
            # "not sure but leans vulnerable" -> vulnerable
            if any(word in text for word in ['leans vulnerable', 'but vulnerable', 'but risky']):
                positive_count += 2  # Give extra weight
            elif any(word in text for word in ['leans safe', 'but safe', 'but secure']):
                negative_count += 2  # Give extra weight
        
        # If we have explicit "not sure" AND no strong indicators, return -1
        # But only if REALLY no other information
        if has_explicit_unsure and positive_count == 0 and negative_count == 0:
            return -1
        
        # If both positive and negative indicators, use the stronger signal
        if positive_count > 0 and negative_count > 0:
            if positive_count > negative_count:
                return 1
            elif negative_count > positive_count:
                return 0
            # Equal counts: check for strong vulnerability keywords
            strong_vuln = ['buffer overflow', 'sql injection', 'use after free', 'exploitable']
            if any(kw in text for kw in strong_vuln):
                return 1
            # Default to not vulnerable if equal (conservative)
            return 0
        
        # Clear positive indicators
        if positive_count > 0:
            return 1
        
        # Clear negative indicators
        if negative_count > 0:
            return 0
        
        # Try to extract numeric answer (0 or 1)
        numbers = re.findall(r'\b[01]\b', text)
        if numbers:
            return int(numbers[0])
        
        # Look for answer patterns at the end of text
        answer_patterns = [
            r'answer[:\s]*([01]|yes|no|vulnerable|not vulnerable|safe|unsafe)',
            r'verdict[:\s]*([01]|yes|no|vulnerable|not vulnerable|safe|unsafe)',
            r'conclusion[:\s]*([01]|yes|no|vulnerable|not vulnerable|safe|unsafe)',
            r'result[:\s]*([01]|yes|no|vulnerable|not vulnerable|safe|unsafe)',
        ]
        
        for pattern in answer_patterns:
            matches = re.findall(pattern, text)
            if matches:
                answer = matches[-1].strip()
                if answer in ['1', 'yes', 'vulnerable', 'unsafe']:
                    return 1
                elif answer in ['0', 'no', 'not vulnerable', 'safe']:
                    return 0
        
        # Sentiment-based fallback: count vulnerability-related words
        vuln_words = ['vulnerability', 'vulnerable', 'risk', 'issue', 'flaw', 'problem', 
                      'overflow', 'injection', 'exploit', 'unsafe', 'insecure']
        safe_words = ['safe', 'secure', 'protected', 'validated', 'checked', 'sanitized']
        
        vuln_word_count = sum(1 for word in vuln_words if word in text)
        safe_word_count = sum(1 for word in safe_words if word in text)
        
        if vuln_word_count > safe_word_count:
            return 1
        elif safe_word_count > vuln_word_count:
            return 0
        
        # Last resort: look at text length and complexity
        # Very short responses without clear indicators -> assume no vulnerability (conservative)
        if len(text.split()) < 5:
            return 0
        
        # Default: if we really can't determine, return -1
        # But this should be rare now with all the above checks
        return -1
    
    @property
    def _type(self) -> str:
        return "vulnerability_parser"


class CodePatchOutputParser(BaseOutputParser[str]):
    """LangChain output parser for extracting code patches from LLM responses."""
    
    def parse(self, text: str) -> str:
        """Parse the LLM output to extract only code, removing explanations.
        
        Args:
            text: Raw LLM output text
            
        Returns:
            Extracted code without explanations
            
        Raises:
            OutputParserException: If parsing fails
        """
        import re
        
        # Try to extract code blocks wrapped in markdown code fences first
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)```', text, re.DOTALL)
        if code_blocks:
            return "\n\n".join(code_blocks).strip()
        
        # If no code blocks, look for code patterns (C/C++ specific)
        # Remove common explanation phrases
        lines = text.split('\n')
        code_lines = []
        skip_patterns = [
            r'^here\s+(is|are)',
            r'^the\s+corrected',
            r'^i\'ve\s+',
            r'^this\s+code',
            r'^explanation',
            r'^note\s*:',
            r'^summary',
            r'^\*\*',
            r'^---',
        ]
        
        in_code_section = False
        for line in lines:
            line_lower = line.strip().lower()
            
            # Skip explanation lines
            if any(re.match(pattern, line_lower) for pattern in skip_patterns):
                continue
            
            # Detect code patterns
            if any([
                line.strip().startswith('//'),
                line.strip().startswith('/*'),
                line.strip().startswith('#include'),
                line.strip().startswith('#define'),
                re.match(r'^\s*\w+\s+\w+\s*\(', line),  # function definition
                re.match(r'^\s*(if|for|while|switch|return|struct|typedef|static|extern)', line),
                '{' in line or '}' in line,
                in_code_section
            ]):
                in_code_section = True
                code_lines.append(line)
            elif in_code_section and line.strip() == '':
                code_lines.append(line)
            elif in_code_section and not line.strip():
                continue
        
        if code_lines:
            return '\n'.join(code_lines).strip()
        
        # Fallback: return original text if no code patterns detected
        return text.strip()
    
    @property
    def _type(self) -> str:
        return "code_patch_parser"


class StrictCWEOutputParser(BaseOutputParser[str]):
    """Ultra-strict LangChain output parser that enforces exact CWE JSON format."""
    
    def parse(self, text: str) -> str:
        """Parse and force-format LLM output to exact CWE JSON list.
        
        Args:
            text: Raw LLM output text
            
        Returns:
            Strictly formatted JSON list: ["CWE-XXX", "CWE-YYY", ...]
            
        Raises:
            OutputParserException: If no valid CWEs can be extracted
        """
        import re
        import json
        
        logger.debug(f"Parsing CWE output: {text[:200]}...")
        
        # Step 1: Try to find existing JSON array (most strict first)
        json_patterns = [
            r'\[\s*"CWE-\d+"\s*(?:,\s*"CWE-\d+"\s*)*\]',  # Perfect format with quotes
            r'\[\s*CWE-\d+\s*(?:,\s*CWE-\d+\s*)*\]',      # Without quotes
            r'\[[\s\S]*?\]',  # Any array-like structure
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                for match in matches:
                    try:
                        # Clean up the match and try to parse
                        cleaned_match = match.strip()
                        
                        # Add quotes if missing around CWE identifiers
                        if '"' not in cleaned_match:
                            cleaned_match = re.sub(r'\b(CWE-\d+)\b', r'"\1"', cleaned_match, flags=re.IGNORECASE)
                        
                        # Try to parse as JSON
                        parsed = json.loads(cleaned_match)
                        if isinstance(parsed, list):
                            # Extract valid CWE identifiers
                            valid_cwes = []
                            for item in parsed:
                                cwe_str = str(item).upper().strip()
                                if re.match(r'^CWE-\d+$', cwe_str):
                                    valid_cwes.append(cwe_str)
                            
                            if len(valid_cwes) >= 3:  # At least 3 valid CWEs found
                                logger.debug(f"Successfully parsed JSON: {valid_cwes[:5]}")
                                return json.dumps(valid_cwes[:5])
                    except Exception as e:
                        logger.debug(f"Failed to parse JSON candidate '{match}': {e}")
                        continue
        
        # Step 2: Extract all CWE mentions and build list
        all_cwes = re.findall(r'CWE-\d+', text, re.IGNORECASE)
        if all_cwes:
            # Remove duplicates, preserve order, uppercase
            seen = set()
            unique_cwes = []
            for cwe in all_cwes:
                cwe_upper = cwe.upper()
                if cwe_upper not in seen and len(unique_cwes) < 5:
                    seen.add(cwe_upper)
                    unique_cwes.append(cwe_upper)
            
            if len(unique_cwes) >= 3:  # At least 3 CWEs required
                logger.debug(f"Extracted CWEs from text: {unique_cwes[:5]}")
                return json.dumps(unique_cwes[:5])
        
        # Step 3: Look for numeric patterns that could be CWE numbers
        numeric_patterns = re.findall(r'\b(\d{1,4})\b', text)
        if numeric_patterns:
            extracted_cwes = []
            for num in numeric_patterns[:5]:
                cwe_id = f"CWE-{num}"
                if cwe_id not in extracted_cwes:
                    extracted_cwes.append(cwe_id)
            
            if len(extracted_cwes) >= 3:  # At least 3 CWEs required
                logger.warning(f"Using numeric extraction: {extracted_cwes[:5]}")
                return json.dumps(extracted_cwes[:5])
        
        # No fallback - raise exception if no valid CWEs found
        logger.error(f"No valid CWEs found in output: {text[:100]}...")
        raise OutputParserException(f"Could not extract valid CWE identifiers from: {text[:100]}...")
    
    @property
    def _type(self) -> str:
        return "strict_cwe_parser"


class ReasoningOutputParser(BaseOutputParser[str]):
    """LangChain output parser for reasoning models to extract only final answers."""
    
    def parse(self, text: str) -> str:
        """Parse reasoning model output to extract only the final answer.
        
        Args:
            text: Raw LLM output text with reasoning
            
        Returns:
            Final answer without reasoning steps
            
        Raises:
            OutputParserException: If parsing fails
        """
        import re
        
        # Look for common final answer patterns
        final_answer_patterns = [
            r'final answer[:\s]*(.+)',
            r'answer[:\s]*(.+)',
            r'conclusion[:\s]*(.+)',
            r'result[:\s]*(.+)',
            r'decision[:\s]*(.+)',
            r'verdict[:\s]*(.+)',
            r'therefore[,\s]*(.+)',
            r'thus[,\s]*(.+)',
            r'hence[,\s]*(.+)',
        ]
        
        text_lower = text.lower()
        
        # Try to find final answer patterns
        for pattern in final_answer_patterns:
            matches = re.findall(pattern, text_lower, re.DOTALL | re.IGNORECASE)
            if matches:
                answer = matches[-1].strip()  # Take the last match
                # Clean up the answer
                answer = re.sub(r'^[:\-\s]+', '', answer)  # Remove leading punctuation
                answer = re.sub(r'[.\s]+$', '', answer)    # Remove trailing punctuation
                if answer and len(answer) < 200:  # Reasonable answer length
                    return answer
        
        # If no clear final answer pattern, try to extract the last meaningful sentence
        sentences = re.split(r'[.!?]+', text)
        for sentence in reversed(sentences):
            sentence = sentence.strip()
            if sentence and len(sentence) > 10 and len(sentence) < 200:
                # Skip reasoning indicators
                if not any(word in sentence.lower() for word in [
                    'thinking', 'reasoning', 'analysis', 'considering', 
                    'let me', 'first', 'next', 'then', 'however', 'but'
                ]):
                    return sentence
        
        # Fallback: return the last line if it's short enough
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        if lines and len(lines[-1]) < 200:
            return lines[-1]
        
        # Final fallback: return original text
        return text.strip()
    
    @property
    def _type(self) -> str:
        return "reasoning_parser"

class LLMManager:
    """Advanced LLM Manager with LangChain integration and multiple model support."""
    
    def __init__(
        self, 
        db_file: Union[str, Path], 
        model_config: Dict[str, Any],
        model_name: str
    ):
        """Initialize the LLM Manager.
        
        Args:
            db_file: Path to the SQLite database
            model_config: Model configuration dictionary
            model_name: Name of the model to use
        """
        self.db_file = Path(db_file)
        self.model_config = model_config
        self.model_name = model_name
        self.db = Database(self.db_file)
        
        # Per-(model, source-db) JSONL log of every LLM response.
        stem = self.db_file.stem
        if stem.startswith("database_"):
            stem = stem[len("database_"):]
        self._response_log_path = self.db_file.parent / "raw_responses" / f"{stem}.jsonl"
        self._response_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize the model based on type
        self.model_type = model_config.get('type', 'unknown')
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        
        # Create necessary columns in the database
        self.create_columns()
        
        # Initialize the specific model
        self._initialize_model()
        
        # Setup output parsers
        self.vuln_parser = VulnerabilityOutputParser()
        self.code_parser = CodePatchOutputParser()
        self.reasoning_parser = ReasoningOutputParser()
        self.cwe_parser = StrictCWEOutputParser()
        self.json_cwe_parser = JsonOutputParser(pydantic_object=CWERankingOutput)
        
        # Check if this is a reasoning model (like gpt-oss)
        self.is_reasoning_model = any(keyword in model_name.lower() for keyword in [
            'gpt-oss', 'reasoning', 'chain-of-thought', 'cot'
        ])
        
        logger.info(f"Initialized LLMManager with model: {model_name} (type: {self.model_type}, reasoning: {self.is_reasoning_model})")
        
        # Batch-commit control: commit every N updates to reduce I/O overhead
        self._commit_batch_size: int = 10
        self._commit_counter: int = 0

    def _maybe_commit(self) -> None:
        """Commit after every N updates to the database."""
        self._commit_counter += 1
        if self._commit_counter % self._commit_batch_size == 0:
            self.db.commit()

    def flush_commits(self) -> None:
        """Force a final commit for any pending updates."""
        self.db.commit()
    
    def _log_response(self, task: str, commit_hash: str, prompt: str, response) -> None:
        """Append the raw LLM response for one sample as JSONL."""
        rec = {
            "ts": time.time(),
            "task": task,
            "model": self.model_name,
            "commit_hash": commit_hash,
            "prompt_chars": len(prompt) if prompt else 0,
            "content": getattr(response, "content", None),
            "probability": getattr(response, "probability", None),
            "raw_response": getattr(response, "raw_response", None),
        }
        with self._response_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    
    def create_columns(self) -> None:
        """Create necessary columns in the database if they do not exist."""
        # Ensure base table exists with required core columns
        if not self.db.table_exists("vulnerabilities"):
            base_columns = [
                "COMMIT_HASH TEXT PRIMARY KEY",
                "VULNERABLE_CODE_BLOCK TEXT",
                "PATCHED_CODE_BLOCK TEXT",
                "VULNERABILITY_YEAR INT",
                "DESCRIPTION_IN_PATCH TEXT",
                "VULNERABILITY_CVE TEXT",
                "VULNERABILITY_CWE TEXT",
                # placeholders that tasks may read before being populated
                "IS_VULNERABLE_Vuln INT",
                "IS_VULNERABLE_Patch INT",
                "IS_VULNERABLE_Vuln_CVE_CWE INT",
                "IS_VULNERABLE_Patch_CVE_CWE INT"
            ]
            self.db.create_table("vulnerabilities", base_columns)
            logger.info("Created base 'vulnerabilities' table as it was missing in the database")

        columns = [          
            "IS_VULNERABLE_Vuln INT",
            "IS_VULNERABLE_Patch INT", 
            "IS_VULNERABLE_Vuln_CVE_CWE INT",
            "IS_VULNERABLE_Patch_CVE_CWE INT",
            # Probability columns
            "IS_VULNERABLE_Vuln_PROB REAL",
            "IS_VULNERABLE_Patch_PROB REAL", 
            "IS_VULNERABLE_Vuln_CVE_CWE_PROB REAL",
            "IS_VULNERABLE_Patch_CVE_CWE_PROB REAL"
        ]
        
        for column_def in columns:
            column_name = column_def.split()[0]
            # Only add column if it doesn't exist
            if not self.db.column_exists("vulnerabilities", column_name):
                self.db.add_column("vulnerabilities", column_def)
            else:
                logger.debug(f"Column {column_name} already exists, skipping")
    
    def _initialize_model(self) -> None:
        """Initialize the specific model based on its type."""
        if self.model_type == 'google':
            self._initialize_google_model()
        elif self.model_type == 'huggingface':
            self._initialize_huggingface_model()
        elif self.model_type == 'openai':
            self._initialize_openai_model()
        elif self.model_type == 'ollama':
            self._initialize_ollama_model()
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def _initialize_google_model(self) -> None:
        """Initialize Google Gemini model."""
        api_key = self._load_api_key(
            self.model_config.get('api_key_file'),
            self.model_config.get('api_key_name')
        )
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(self.model_config['model_name'])
        
        # Set up rate limiting for free tier
        self.rate_limit_rpm = self.model_config.get('rate_limit_rpm', 10)
        self.rate_limit_delay = self.model_config.get('rate_limit_delay', 6)
        self.last_request_time = 0
        
        logger.info(f"Initialized Google model: {self.model_config['model_name']} with rate limit: {self.rate_limit_rpm} RPM")
    
    def _initialize_huggingface_model(self) -> None:
        """Initialize HuggingFace model with GPU-only configuration."""
        model_name = self.model_config['model_name']

        # Check if this is a PEFT/LoRA model
        use_peft = self.model_config.get('use_peft', False)
        adapter_path = self.model_config.get('adapter_path', None)

        # Validate model exists first
        logger.info(f"Attempting to load HuggingFace model: {model_name}")
        if use_peft and adapter_path:
            logger.info(f"PEFT mode enabled - will load adapter from: {adapter_path}")

        # Force GPU-only usage
        if not torch.cuda.is_available():
            raise RuntimeError("GPU is required but CUDA is not available. Cannot proceed.")
        
        gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3  # GB
        free_memory = (torch.cuda.get_device_properties(0).total_memory - torch.cuda.memory_allocated(0)) / 1024**3  # GB
        logger.info(f"GPU memory: {gpu_memory:.1f}GB total, {free_memory:.1f}GB free")
        
        if free_memory < 6.0:
            logger.warning(f"Limited GPU memory ({free_memory:.1f}GB free), but proceeding as requested")
        
        use_gpu = True
        logger.info("Using GPU (forced mode)")
        
        # Get HuggingFace token if available
        hf_token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
        if hf_token:
            logger.info("Using HuggingFace authentication token")

        # Handle PEFT/LoRA models with manual loading
        if use_peft and adapter_path:
            try:
                logger.info(f"Loading base model: {model_name}")

                # Determine dtype based on model type
                if ("llama-4" in model_name.lower() or "llama4" in model_name.lower() or
                    "deepseek" in model_name.lower() or "qwen3" in model_name.lower() or
                    "codellama" in model_name.lower()):
                    torch_dtype = torch.bfloat16
                    attn_impl = "eager"
                else:
                    torch_dtype = torch.float16
                    attn_impl = None

                # Prepare loading kwargs
                load_kwargs = {
                    "torch_dtype": torch_dtype,
                    "device_map": "auto",
                    "trust_remote_code": True,
                    "low_cpu_mem_usage": True
                }
                if attn_impl:
                    load_kwargs["attn_implementation"] = attn_impl
                if hf_token:
                    load_kwargs["token"] = hf_token

                # Load base model
                base_model = AutoModelForCausalLM.from_pretrained(model_name, **load_kwargs)
                logger.info(f"Base model loaded successfully")

                # Load tokenizer
                tokenizer_kwargs = {"trust_remote_code": True}
                if hf_token:
                    tokenizer_kwargs["token"] = hf_token
                self.tokenizer = AutoTokenizer.from_pretrained(model_name, **tokenizer_kwargs)

                # Configure tokenizer for PEFT - critical for avoiding CUDA errors
                if self.tokenizer.pad_token is None:
                    self.tokenizer.pad_token = self.tokenizer.eos_token
                self.tokenizer.padding_side = "left"  # Important for causal LMs

                logger.info(f"Tokenizer loaded successfully (vocab_size={len(self.tokenizer)})")

                # Load PEFT adapter
                logger.info(f"Loading PEFT adapter from: {adapter_path}")
                self.model = PeftModel.from_pretrained(base_model, adapter_path)

                self.model.eval()  # Set to evaluation mode

                # Log vocab compatibility info
                model_vocab_size = self.model.get_base_model().get_input_embeddings().num_embeddings
                logger.info(f"Successfully loaded PEFT model with adapter from {adapter_path}")
                logger.info(f"Model vocab: {model_vocab_size}, Tokenizer vocab: {len(self.tokenizer)}")

                # Set pipeline to None since we're using manual model
                self.pipeline = None
                return

            except Exception as e:
                logger.error(f"Failed to load PEFT model: {e}")
                raise RuntimeError(f"Failed to initialize PEFT model {model_name} with adapter {adapter_path}: {e}") from e

        # Common model loading kwargs (excluding trust_remote_code and token which go to pipeline directly)
        model_kwargs = {
            "low_cpu_mem_usage": True
        }

        # Special settings for Llama 4, DeepSeek R1, Qwen3 Coder, and CodeLlama models
        if ("llama-4" in model_name.lower() or "llama4" in model_name.lower() or
            "deepseek" in model_name.lower() or "qwen3" in model_name.lower() or
            "codellama" in model_name.lower()):
            logger.info(f"Detected special model ({model_name}), using bfloat16 and eager attention")
            selected_dtype = torch.bfloat16
            model_kwargs["attn_implementation"] = "eager"
        else:
            selected_dtype = torch.float16
        
        # Pipeline arguments
        # Use device_map="auto" for large models to distribute across GPUs
        pipeline_kwargs = {
            "task": "text-generation",
            "model": model_name,
            "tokenizer": model_name,
            "dtype": selected_dtype,
            "trust_remote_code": True,
            "model_kwargs": model_kwargs,
            "device_map": "auto"  # Auto-distribute across available GPUs
        }
        
        # Add token if available
        if hf_token:
            pipeline_kwargs["token"] = hf_token
        
        try:
            # GPU-only pipeline initialization
            self.pipeline = pipeline(**pipeline_kwargs)
            
            # Configure tokenizer padding token if missing (e.g., for Llama models)
            if self.pipeline.tokenizer.pad_token is None:
                self.pipeline.tokenizer.pad_token = self.pipeline.tokenizer.eos_token
                logger.info(f"Set pad_token to eos_token for {model_name}")
            
            logger.info(f"Initialized HuggingFace pipeline on GPU: {model_name}")
                
        except (ValueError, KeyError) as e:
            # Handle custom model types or incompatible architectures
            if "model type" in str(e).lower() or "not recognize" in str(e).lower():
                logger.error(f"Model '{model_name}' uses an incompatible or unrecognized architecture: {e}")
                logger.error(f"This model may require a specific version of transformers or custom code.")
                logger.error(f"Please verify the model exists and is compatible with your transformers version.")
                raise ValueError(f"Incompatible model architecture for {model_name}. "
                               f"Try: pip install --upgrade transformers or use a different model.") from e
            elif "sentencepiece" in str(e).lower():
                logger.error(f"Model '{model_name}' requires sentencepiece tokenizer: {e}")
                logger.error(f"Please install sentencepiece: pip install sentencepiece")
                raise ValueError(f"Missing sentencepiece dependency for {model_name}. "
                               f"Install with: pip install sentencepiece protobuf") from e
            else:
                logger.warning(f"Failed to initialize pipeline, trying manual loading: {e}")
            
            # Fallback to manual loading with better error handling (GPU-only)
            try:
                # Manual loading kwargs
                manual_kwargs = {
                    "trust_remote_code": True,
                    "low_cpu_mem_usage": True
                }
                if hf_token:
                    manual_kwargs["token"] = hf_token
                
                # Special settings for Llama 4 and DeepSeek R1
                if ("llama-4" in model_name.lower() or "llama4" in model_name.lower() or "deepseek" in model_name.lower()):
                    manual_kwargs["attn_implementation"] = "eager"
                    manual_torch_dtype = torch.bfloat16
                else:
                    manual_torch_dtype = torch.float16
                
                self.tokenizer = AutoTokenizer.from_pretrained(model_name, **manual_kwargs)
                
                # Load model and move explicitly to GPU
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype=manual_torch_dtype,
                    **manual_kwargs
                )
                if torch.cuda.is_available():
                    self.model.to("cuda")
                    logger.info("Moved model to cuda:0 explicitly")
                logger.info(f"Initialized HuggingFace model manually on GPU: {model_name}")
                    
            except (ValueError, KeyError) as e2:
                # Handle custom model types in manual loading too
                if "model type" in str(e2).lower() or "not recognize" in str(e2).lower():
                    logger.error(f"Model '{model_name}' uses an incompatible architecture (manual load attempt): {e2}")
                    raise ValueError(f"Model {model_name} is not compatible. Please use a different model or update transformers.") from e2
                elif "sentencepiece" in str(e2).lower():
                    logger.error(f"Model '{model_name}' requires sentencepiece tokenizer (manual load): {e2}")
                    logger.error(f"Please install sentencepiece: pip install sentencepiece protobuf")
                    raise ValueError(f"Missing sentencepiece dependency for {model_name}. "
                                   f"Install with: pip install sentencepiece protobuf") from e2
                else:
                    logger.error(f"Failed to initialize model: {e2}")
                    raise
    
    def _initialize_openai_model(self) -> None:
        """Initialize OpenAI model."""
        # For now, we'll use the API similar to Google
        # This would need proper OpenAI SDK integration
        api_key = self._load_api_key(
            self.model_config.get('api_key_file'),
            self.model_config.get('api_key_name')
        )
        # Store the API key for later use
        self.openai_api_key = api_key
        logger.info(f"Initialized OpenAI model: {self.model_config['model_name']}")
    
    def _initialize_ollama_model(self) -> None:
        """Initialize Ollama model."""
        self.api_url = self.model_config.get('api_url', 'http://localhost:11434/api/generate')
        self.context_length = self.model_config.get('context_length', 8192)
        logger.info(f"Initialized Ollama model: {self.model_config['model_name']} with context length: {self.context_length}")
    
    def _load_api_key(self, key_file: str, key_name: str) -> str:
        """Load API key from configuration file.
        
        Args:
            key_file: Path to the key file
            key_name: Name of the key in the file
            
        Returns:
            API key string
        """
        if not key_file or not key_name:
            raise ValueError("API key file and name must be specified")
        
        key_path = Path(key_file)
        if not key_path.exists():
            raise FileNotFoundError(f"API key file not found: {key_path}")
        
        # Try to parse as config file
        try:
            config = configparser.ConfigParser()
            config.read(key_path)
            return config['DEFAULT'][key_name]
        except:
            # Try to parse as simple key=value format
            with open(key_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f'{key_name} ='):
                        return line.split('=', 1)[1].strip().strip('"')
            
        raise ValueError(f"Could not find API key '{key_name}' in file '{key_path}'")
    
    def query_model(
        self, 
        prompt: str, 
        max_retries: int = 3, 
        retry_delay: int = 2,
        return_probabilities: bool = True
    ) -> LLMResponse:
        """Query the model and return response with probability information.
        
        Args:
            prompt: The prompt to send to the model
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            return_probabilities: Whether to return probability information
            
        Returns:
            LLMResponse object with content and probability information
        """
        for attempt in range(max_retries):
            try:
                if self.model_type == 'google':
                    return self._query_google_model(prompt, return_probabilities)
                elif self.model_type == 'huggingface':
                    return self._query_huggingface_model(prompt, return_probabilities)
                elif self.model_type == 'openai':
                    return self._query_openai_model(prompt, return_probabilities)
                elif self.model_type == 'ollama':
                    return self._query_ollama_model(prompt, return_probabilities)
                else:
                    raise ValueError(f"Unsupported model type: {self.model_type}")
                    
            except Exception as e:
                error_str = str(e)
                logger.error(f"Error querying model (attempt {attempt + 1}/{max_retries}): {e}")
                
                # Handle quota errors with longer delays
                if "429" in error_str or "quota" in error_str.lower():
                    if attempt < max_retries - 1:
                        # Extract suggested retry delay from error message
                        import re
                        retry_match = re.search(r'retry in (\d+(?:\.\d+)?)s', error_str)
                        if retry_match:
                            suggested_delay = float(retry_match.group(1))
                            # Add some buffer to the suggested delay
                            actual_delay = min(suggested_delay + 5, 60)  # Max 60 seconds
                            logger.info(f"Quota error: waiting {actual_delay}s before retry")
                            time.sleep(actual_delay)
                        else:
                            # Default longer delay for quota errors
                            quota_delay = min(retry_delay * (2 ** attempt), 60)  # Exponential backoff, max 60s
                            logger.info(f"Quota error: waiting {quota_delay}s before retry")
                            time.sleep(quota_delay)
                    else:
                        logger.error("Max retries reached for quota error")
                        return LLMResponse(content="", probability=None)
                else:
                    # Regular error handling
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                    else:
                        logger.error("Max retries reached")
                        return LLMResponse(content="", probability=None)
        
        return LLMResponse(content="", probability=None)
    
    def _query_google_model(self, prompt: str, return_probabilities: bool) -> LLMResponse:
        """Query Google Gemini model with rate limiting."""
        import time
        
        # Rate limiting: ensure we don't exceed the quota
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        try:
            # Configure generation parameters for more reliable responses
            generation_config = genai.types.GenerationConfig(
                temperature=_llm_temperature(),
                top_p=0.8,
                top_k=40,
                max_output_tokens=512,
            )
            
            # Configure safety settings to allow security analysis
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH", 
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_ONLY_HIGH"  # Allow security code analysis
                }
            ]
            
            response = self.model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=safety_settings
            )
            
            self.last_request_time = time.time()
            
            # Check if response was blocked by safety filters
            if not response.candidates or len(response.candidates) == 0:
                logger.warning("Response blocked by safety filters - no candidates returned")
                return LLMResponse(
                    content="",
                    probability=None,
                    raw_response="BLOCKED_BY_SAFETY_FILTERS"
                )
            
            candidate = response.candidates[0]
            
            # Check finish reason
            if hasattr(candidate, 'finish_reason'):
                finish_reason = candidate.finish_reason
                if finish_reason == 2:  # SAFETY
                    logger.warning("Response blocked by safety filters - finish_reason is SAFETY")
                    return LLMResponse(
                        content="",
                        probability=None,
                        raw_response="BLOCKED_BY_SAFETY_FILTERS"
                    )
                elif finish_reason == 3:  # RECITATION
                    logger.warning("Response blocked due to recitation - finish_reason is RECITATION")
                    return LLMResponse(
                        content="",
                        probability=None,
                        raw_response="BLOCKED_BY_RECITATION"
                    )
            
            # Try to get the text content
            try:
                content = response.text
            except Exception as e:
                logger.warning(f"Could not access response.text: {e}")
                # Try to get content from parts directly
                if hasattr(candidate, 'content') and hasattr(candidate.content, 'parts'):
                    parts = candidate.content.parts
                    if parts:
                        content = ''.join([part.text for part in parts if hasattr(part, 'text')])
                    else:
                        content = ""
                else:
                    content = ""
            
            # Extract probability information if available
            probability = None
            
            if return_probabilities and hasattr(response, 'candidates'):
                # Try to extract probability from safety ratings or other metadata
                if response.candidates and len(response.candidates) > 0:
                    candidate = response.candidates[0]
                    if hasattr(candidate, 'safety_ratings') and candidate.safety_ratings:
                        # Use safety ratings as a proxy for probability
                        total_ratings = len(candidate.safety_ratings)
                        if total_ratings > 0:
                            negligible_count = len([r for r in candidate.safety_ratings if hasattr(r.probability, 'name') and r.probability.name == 'NEGLIGIBLE'])
                            probability = negligible_count / total_ratings
                        else:
                            probability = None
                    else:
                        probability = None
            
            return LLMResponse(
                content=content,
                probability=probability,
                raw_response=str(response)
            )
            
        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "quota" in error_str.lower():
                # Extract retry delay from error message if available
                import re
                retry_match = re.search(r'retry in (\d+(?:\.\d+)?)s', error_str)
                if retry_match:
                    retry_delay = float(retry_match.group(1))
                    logger.warning(f"Quota exceeded, suggested retry delay: {retry_delay}s")
                    # For quota errors, we'll let the upper level retry logic handle it
                else:
                    logger.warning("Quota exceeded, using default retry delay")
            raise
    
    def _query_huggingface_model(self, prompt: str, return_probabilities: bool) -> LLMResponse:
        """Query HuggingFace model with proper device handling and probability estimate."""
        
        # For Gemma, ALWAYS use pipeline to avoid CUDA assertion errors completely
        if 'gemma' in self.model_name.lower():
            logger.info(f"Using pipeline-only mode for Gemma (skipping probabilities): {self.model_name}")
            if self.pipeline:
                try:
                    # Add proper Gemma-specific prompt formatting
                    # Gemma models often need more explicit instruction formatting
                    gemma_prompt = f"<start_of_turn>user\n{prompt.strip()}<end_of_turn>\n<start_of_turn>model\n"
                    
                    logger.debug(f"Gemma formatted prompt: {gemma_prompt[:200]}...")
                    
                    # Use Gemma-optimized pipeline configuration
                    result = self.pipeline(
                        gemma_prompt,
                        max_new_tokens=50,  # Shorter for simple responses
                        min_new_tokens=1,   # Ensure at least some output
                        **_sampling_kwargs(_llm_temperature()),
                        return_full_text=False,
                        eos_token_id=self.pipeline.tokenizer.eos_token_id,
                        pad_token_id=self.pipeline.tokenizer.pad_token_id
                    )
                    
                    logger.debug(f"Gemma raw result: {result}")
                    
                    # Better result extraction with debugging
                    if result and len(result) > 0:
                        content = result[0].get('generated_text', '') if isinstance(result[0], dict) else str(result[0])
                        content = content.strip()
                        
                        if content:
                            probability = None  # Never calculate probabilities for Gemma
                            logger.debug(f"Gemma pipeline generation successful: '{content[:50]}...'")
                        else:
                            logger.warning(f"Gemma pipeline returned empty content with chat format. Trying simple format...")
                            # Fallback: try without chat formatting
                            simple_result = self.pipeline(
                                prompt.strip(),
                                max_new_tokens=50,
                                **_sampling_kwargs(_llm_temperature()),
                                return_full_text=False
                            )
                            if simple_result and len(simple_result) > 0:
                                content = simple_result[0].get('generated_text', '') if isinstance(simple_result[0], dict) else str(simple_result[0])
                                content = content.strip()
                                logger.debug(f"Gemma simple format worked: '{content[:50]}...'")
                            else:
                                content = ""
                            probability = None
                    else:
                        logger.warning(f"Gemma pipeline returned no results. Result: {result}")
                        content = ""
                        probability = None
                        
                except Exception as e:
                    logger.error(f"Gemma pipeline generation failed: {e}")
                    logger.error(f"Prompt was: {prompt[:100]}...")
                    # Clear CUDA cache on error
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                    content = ""
                    probability = None
            else:
                logger.error(f"No pipeline available for Gemma: {self.model_name}")
                content = ""
                probability = None
            
            return LLMResponse(
                content=content,
                probability=probability,
                raw_response=content
            )
        
        # For Qwen3 Coder, use standard approach but without probabilities
        if 'qwen3' in self.model_name.lower():
            logger.info(f"Using standard mode for Qwen3 Coder (skipping probabilities): {self.model_name}")
            # Continue to standard processing below but ensure no probability calculation
        
        # For all other models, use the existing logic
        # Prefer direct model.generate to enable score outputs; pull from pipeline if necessary
        local_model = self.model
        local_tokenizer = self.tokenizer
        if self.pipeline:
            try:
                if not local_model:
                    local_model = self.pipeline.model
                if not local_tokenizer:
                    local_tokenizer = self.pipeline.tokenizer
            except Exception:
                pass

        content = ""
        probability = None

        if local_model is not None and local_tokenizer is not None:
            try:
                # Proper tokenization with padding and attention mask
                # Use model's maximum context length if available, otherwise use safe defaults
                use_peft = self.model_config.get('use_peft', False)
                
                # Try to get max context length from model config or tokenizer
                if 'context_length' in self.model_config:
                    max_len = self.model_config['context_length']
                elif hasattr(local_tokenizer, 'model_max_length') and local_tokenizer.model_max_length < 1000000:
                    # Use tokenizer's max length if it's reasonable (not infinity)
                    max_len = local_tokenizer.model_max_length
                else:
                    # Fallback to safe defaults
                    max_len = 2048 if use_peft else 4096
                
                logger.debug(f"Using max_length={max_len} for tokenization")

                tokenized = local_tokenizer(
                    prompt,
                    return_tensors='pt',
                    padding=True,
                    truncation=True,
                    max_length=max_len,
                    return_attention_mask=True
                )

                model_device = next(local_model.parameters()).device
                input_ids = tokenized['input_ids'].to(model_device)
                attention_mask = tokenized['attention_mask'].to(model_device)

                with torch.no_grad():
                    # Check if this is a problematic model for probability calculation
                    # Note: PEFT models with adapters should disable probability calculation to avoid issues
                    use_peft = self.model_config.get('use_peft', False)
                    is_problematic_model = use_peft or any(name in self.model_name.lower() for name in ['llama-4', 'deepseek'])

                    # Ensure pad_token_id is set
                    pad_token_id = local_tokenizer.pad_token_id
                    if pad_token_id is None:
                        pad_token_id = local_tokenizer.eos_token_id

                    # For PEFT models, use greedy decoding to avoid CUDA errors with long prompts
                    eos_token_id = local_tokenizer.eos_token_id

                    if use_peft:
                        gen_kwargs = {
                            "max_new_tokens": 256,  # Shorter for simple yes/no or CWE responses
                            "do_sample": False,  # Greedy decoding for PEFT models
                            "pad_token_id": pad_token_id,
                            "eos_token_id": eos_token_id,
                            "attention_mask": attention_mask,
                            "return_dict_in_generate": True,
                        }
                        logger.debug("Using greedy decoding for PEFT model")
                    else:
                        gen_kwargs = {
                            "max_new_tokens": 512,
                            "pad_token_id": pad_token_id,
                            "eos_token_id": eos_token_id,
                            "attention_mask": attention_mask,
                            "return_dict_in_generate": True,
                            **_sampling_kwargs(_llm_temperature()),
                        }
                    
                    # Enable output_scores for safe models only
                    if return_probabilities and not is_problematic_model:
                        gen_kwargs["output_scores"] = True

                    outputs = local_model.generate(input_ids, **gen_kwargs)

                # Free intermediate activations between samples
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()

                # Decode only the new tokens
                sequences = outputs.sequences
                new_tokens = sequences[0, input_ids.shape[1]:]
                content = local_tokenizer.decode(new_tokens, skip_special_tokens=True)

                # Compute average token probability of generated tokens (proxy) - only for safe models
                if return_probabilities and hasattr(outputs, 'scores') and outputs.scores and not is_problematic_model:
                    try:
                        import torch.nn.functional as F
                        probs = []
                        for t, logits in enumerate(outputs.scores):
                            try:
                                # logits: [batch, vocab]
                                # Clamp logits to prevent extreme values
                                clamped_logits = torch.clamp(logits[0], min=-100, max=100)
                                
                                # Use more stable softmax with temperature
                                step_probs = F.softmax(clamped_logits / 1.0, dim=-1)
                                
                                token_id = new_tokens[t].item() if t < new_tokens.shape[0] else None
                                if token_id is not None and token_id < step_probs.size(0):
                                    prob_value = step_probs[token_id].item()
                                    
                                    # Additional safety checks
                                    if (not torch.isnan(torch.tensor(prob_value)) and 
                                        not torch.isinf(torch.tensor(prob_value)) and 
                                        0.0 <= prob_value <= 1.0):
                                        probs.append(prob_value)
                            except Exception as step_e:
                                logger.debug(f"Skipping probability calculation for step {t}: {step_e}")
                                continue
                        
                        if probs:
                            # Use geometric mean to avoid length bias; add small epsilon for stability
                            import math
                            log_sum = sum(math.log(max(p, 1e-12)) for p in probs)
                            probability = math.exp(log_sum / len(probs))
                        else:
                            probability = None
                    except Exception as prob_e:
                        logger.warning(f"Probability calculation failed for {self.model_name}, disabling: {prob_e}")
                        probability = None
                else:
                    probability = None
                    
            except Exception as e:
                logger.error(f"HuggingFace generation (manual) failed: {e}")
                # Clear CUDA cache on error and try to recover
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                    torch.cuda.synchronize()
                
                # For critical CUDA errors, disable output_scores permanently for this model
                if "assert" in str(e).lower() or "cuda" in str(e).lower():
                    logger.warning(f"CUDA assertion error detected for {self.model_name}, switching to safe mode")
                    # Try one more time without output_scores
                    try:
                        safe_gen_kwargs = {
                            "max_new_tokens": 512,
                            "do_sample": False,  # Use greedy decoding for stability
                            "temperature": 0,
                            "pad_token_id": (local_tokenizer.eos_token_id if getattr(local_tokenizer, 'eos_token_id', None) is not None else getattr(local_tokenizer, 'pad_token_id', None)),
                            "attention_mask": torch.ones_like(input_ids),
                            "return_dict_in_generate": True,
                            # Explicitly disable any probability-related outputs
                        }
                        outputs = local_model.generate(input_ids, **safe_gen_kwargs)
                        
                        sequences = outputs.sequences
                        new_tokens = sequences[0, input_ids.shape[1]:]
                        content = local_tokenizer.decode(new_tokens, skip_special_tokens=True)
                        probability = None
                        
                        logger.info(f"Successfully recovered from CUDA error for {self.model_name}")
                    except Exception as e2:
                        logger.error(f"Safe mode generation also failed: {e2}")
                        content = ""
                        probability = None
                else:
                    content = ""
                    probability = None
        else:
            # Fallback to pipeline simple generation (no probability guaranteed)
            if self.pipeline:
                try:
                    result = self.pipeline(
                        prompt,
                        max_new_tokens=512,
                        **_sampling_kwargs(_llm_temperature()),
                        return_full_text=False,
                        pad_token_id=self.pipeline.tokenizer.eos_token_id if self.pipeline.tokenizer.eos_token_id else self.pipeline.tokenizer.pad_token_id
                    )
                    content = result[0]['generated_text'] if result else ""
                    probability = None
                except Exception as e:
                    logger.error(f"Pipeline generation failed: {e}")
                    # Clear CUDA cache on error
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                    content = ""
                    probability = None

        return LLMResponse(
            content=content,
            probability=probability,
            raw_response=content
        )
    
    def _query_openai_model(self, prompt: str, return_probabilities: bool) -> LLMResponse:
        """Query OpenAI model."""
        # This is a placeholder - would need proper OpenAI SDK integration
        import requests
        
        headers = {
            'Authorization': f'Bearer {self.openai_api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': self.model_config['model_name'],
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': _llm_temperature(),
            'max_tokens': 512
        }
        
        if return_probabilities:
            data['logprobs'] = True
            data['top_logprobs'] = 5
        
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            content = result['choices'][0]['message']['content']
            
            # Extract probability information
            probability = None
            if return_probabilities and 'logprobs' in result['choices'][0]:
                logprobs = result['choices'][0]['logprobs']
                if logprobs and 'content' in logprobs:
                    # Calculate average probability
                    probs = [token.get('logprob', 0) for token in logprobs['content'] if token.get('logprob')]
                    if probs:
                        probability = sum(probs) / len(probs)
            
            return LLMResponse(
                content=content,
                probability=probability,
                raw_response=str(result)
            )
        else:
            raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")
    
    def _query_ollama_model(self, prompt: str, return_probabilities: bool) -> LLMResponse:
        """Query Ollama API."""
        payload = {
            'model': self.model_config['model_name'],
            'prompt': prompt,
            'stream': False,
            'options': {
                'num_ctx': self.context_length,
                'temperature': _llm_temperature(),
                'num_predict': 512
            }
        }
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=300)
            response.raise_for_status()
            
            result = response.json()
            content = result.get('response', '').strip()
            
            # Ollama doesn't provide token probabilities in the same way
            # We can use eval_count and eval_duration as a proxy for confidence
            probability = None
            if return_probabilities and 'eval_count' in result and 'eval_duration' in result:
                # Normalize to 0-1 range (tokens per second as a rough proxy)
                eval_count = result.get('eval_count', 0)
                eval_duration = result.get('eval_duration', 1)
                if eval_duration > 0:
                    tokens_per_sec = (eval_count / eval_duration) * 1e9  # Convert ns to s
                    # Normalize (assuming 10-100 tokens/sec is normal range)
                    probability = min(max((tokens_per_sec - 10) / 90, 0.0), 1.0)
            
            return LLMResponse(
                content=content,
                probability=probability,
                raw_response=str(result)
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API error: {e}")
            raise Exception(f"Ollama API error: {e}")
    
    def is_vulnerable_func(
        self, 
        commit_hash: str, 
        code_block: str, 
        is_vulnerable: bool = True,
        force_reprocess: bool = False
    ) -> None:
        """Check if the code block is vulnerable or not using LangChain parsing.
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
            force_reprocess: Whether to reprocess even if result already exists
        """
        # Check if result already exists and skip if not forcing reprocess
        if not force_reprocess:
            status_col = 'IS_VULNERABLE_Vuln' if is_vulnerable else 'IS_VULNERABLE_Patch'
            result = self.db.execute(f"""
                SELECT {status_col} FROM vulnerabilities 
                WHERE COMMIT_HASH = ?
            """, (commit_hash,)).fetchone()
            
            if result and result[0] is not None and str(result[0]).strip() != '':
                logger.debug(f"Skipping {commit_hash[:8]} - already has result: {result[0]}")
                return
        prompt_template = PromptTemplate(
            input_variables=["code_block"],
            template="""Check if the following C code block is vulnerable. 
Respond with ONLY one of these options:
- '1' if the code is vulnerable
- '0' if the code is not vulnerable  
- 'not sure' if you are not sure if it is vulnerable or not

Do not include any explanation or additional text.

Code block:
{code_block}

Response:"""
        )
        
        prompt = prompt_template.format(code_block=code_block)
        
        # For Gemma, Qwen3 Coder, CodeLlama, and PEFT models, never try to calculate probabilities - just get the response
        use_peft = self.model_config.get('use_peft', False)
        if use_peft or any(name in self.model_name.lower() for name in ['gemma', 'qwen3', 'codellama', 'megavul']):
            response = self.query_model(prompt, return_probabilities=False)
            # Don't attempt any probability calculation for these models
        else:
            # For other models, use normal probability calculation
            response = self.query_model(prompt, return_probabilities=True)
        
        self._log_response(
            'is_vulnerable_vuln' if is_vulnerable else 'is_vulnerable_patch',
            commit_hash, prompt, response,
        )
        
        if response.content:
            try:
                # For reasoning models, first extract the final answer, then parse vulnerability
                if self.is_reasoning_model:
                    final_answer = self.reasoning_parser.parse(response.content)
                    status = self.vuln_parser.parse(final_answer)
                else:
                    # Use LangChain parser directly
                    status = self.vuln_parser.parse(response.content)
                
                # Determine column names
                if is_vulnerable:
                    status_col = 'IS_VULNERABLE_Vuln'
                    prob_col = 'IS_VULNERABLE_Vuln_PROB'
                else:
                    status_col = 'IS_VULNERABLE_Patch' 
                    prob_col = 'IS_VULNERABLE_Patch_PROB'
                
                # Update database with status and probability information
                prob_rounded = round(response.probability, 2) if response.probability is not None else None
                self.db.execute(f"""
                    UPDATE vulnerabilities
                    SET {status_col} = ?, {prob_col} = ?
                    WHERE COMMIT_HASH = ?
                """, (status, prob_rounded, commit_hash))
                self._maybe_commit()  # Batched commit
                
                logger.info(f"✓ Vulnerability check result ({status}) with probability ({response.probability}) SAVED to database for commit {commit_hash[:8]}")
                
            except OutputParserException as e:
                logger.warning(f"Failed to parse vulnerability response for commit_hash {commit_hash}: {e}")
                # Store raw response if parsing fails
                status_col = 'IS_VULNERABLE_Vuln' if is_vulnerable else 'IS_VULNERABLE_Patch'
                self.db.execute(f"""
                    UPDATE vulnerabilities
                    SET {status_col} = ?
                    WHERE COMMIT_HASH = ?
                """, (response.content, commit_hash))
                self._maybe_commit()
        elif response.raw_response and "BLOCKED" in response.raw_response:
            # Handle blocked responses
            logger.warning(f"Response blocked by safety filters for commit_hash {commit_hash}: {response.raw_response}")
            
            # For blocked responses, we can't determine vulnerability, so mark as NULL or skip
            # This allows the job to continue rather than fail
            status_col = 'IS_VULNERABLE_Vuln' if is_vulnerable else 'IS_VULNERABLE_Patch'
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {status_col} = ?
                WHERE COMMIT_HASH = ?
            """, (None, commit_hash))  # NULL indicates blocked/unknown
            self._maybe_commit()
        else:
            logger.error(f"Failed to check vulnerability for commit_hash {commit_hash}: Empty response content")
            logger.error(f"Raw response: {response.raw_response}")
            logger.error(f"Response probability: {response.probability}")
            # For Gemma, try to store something to avoid completely empty records
            if 'gemma' in self.model_name.lower():
                status_col = 'IS_VULNERABLE_Vuln' if is_vulnerable else 'IS_VULNERABLE_Patch'
                # Store a default "not sure" response for empty Gemma responses
                self.db.execute(f"""
                    UPDATE vulnerabilities
                    SET {status_col} = ?
                    WHERE COMMIT_HASH = ?
                """, (-1, commit_hash))  # -1 indicates "not sure"
                self._maybe_commit()
                logger.info(f"Stored default 'not sure' response for empty Gemma output: {commit_hash[:8]}")
            else:
                logger.error(f"Failed to check vulnerability for commit_hash {commit_hash}")
    
    def is_vulnerable_to_CVE_CWE(
        self,
        commit_hash: str,
        code_block: str,
        cve: str,
        cwe,
        is_vulnerable: bool = True
    ) -> None:
        """Check if the code block is vulnerable to a specific CVE/CWE using LangChain parsing.
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            cve: CVE identifier
            cwe: CWE identifier
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
        """
        # Normalize CWE(s) which may be a JSON array string or a list
        def _normalize_cwes(cwe_value) -> List[str]:
            try:
                if isinstance(cwe_value, list):
                    return [str(x).strip() for x in cwe_value if str(x).strip()]
                s = str(cwe_value).strip()
                if not s:
                    return []
                import json as _json
                parsed = _json.loads(s)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
                return [str(parsed).strip()]
            except Exception:
                # fallback: split by commas if not valid JSON
                s = str(cwe_value).strip().strip("[]")
                return [p.strip() for p in s.replace(";", ",").split(",") if p.strip()]

        cwe_list = _normalize_cwes(cwe)
        cwe_for_prompt = " or ".join(cwe_list) if cwe_list else "CWE"

        prompt_template = PromptTemplate(
            input_variables=["code_block", "cve", "cwe_list"],
            template="""Check if the following C code block is vulnerable to the specific CVE ({cve}) and CWE(s) ({cwe_list}). 
Respond with ONLY one of these options:
- '1' if the code is vulnerable
- '0' if the code is not vulnerable  
- 'not sure' if you are not sure if it is vulnerable or not

Do not include any explanation or additional text.

Code block:
{code_block}

Response:"""
        )
        
        prompt = prompt_template.format(code_block=code_block, cve=cve, cwe_list=cwe_for_prompt)
        
        # For Gemma, Qwen3 Coder, CodeLlama, and PEFT models, never try to calculate probabilities - just get the response
        use_peft = self.model_config.get('use_peft', False)
        if use_peft or any(name in self.model_name.lower() for name in ['gemma', 'qwen3', 'codellama', 'megavul']):
            response = self.query_model(prompt, return_probabilities=False)
            # Don't attempt any probability calculation for these models
        else:
            # For other models, use normal probability calculation
            response = self.query_model(prompt, return_probabilities=True)
        
        self._log_response(
            'is_vulnerable_vuln_cve_cwe' if is_vulnerable else 'is_vulnerable_patch_cve_cwe',
            commit_hash, prompt, response,
        )
        
        if response.content:
            try:
                # For reasoning models, first extract the final answer, then parse vulnerability
                if self.is_reasoning_model:
                    final_answer = self.reasoning_parser.parse(response.content)
                    status = self.vuln_parser.parse(final_answer)
                else:
                    # Use LangChain parser directly
                    status = self.vuln_parser.parse(response.content)
                
                # Determine column names
                if is_vulnerable:
                    status_col = 'IS_VULNERABLE_Vuln_CVE_CWE'
                    prob_col = 'IS_VULNERABLE_Vuln_CVE_CWE_PROB'
                else:
                    status_col = 'IS_VULNERABLE_Patch_CVE_CWE'
                    prob_col = 'IS_VULNERABLE_Patch_CVE_CWE_PROB'
                
                # Update database with status and probability information
                prob_rounded = round(response.probability, 2) if response.probability is not None else None
                self.db.execute(f"""
                    UPDATE vulnerabilities
                    SET {status_col} = ?, {prob_col} = ?
                    WHERE COMMIT_HASH = ?
                """, (status, prob_rounded, commit_hash))
                self._maybe_commit()
                
                logger.info(f"✓ CVE/CWE check result ({status}) with probability ({response.probability}) SAVED to database for commit {commit_hash[:8]}")
                
            except OutputParserException as e:
                logger.warning(f"Failed to parse specific CVE/CWE vulnerability response for commit_hash {commit_hash}: {e}")
                # Store raw response if parsing fails
                status_col = 'IS_VULNERABLE_Vuln_CVE_CWE' if is_vulnerable else 'IS_VULNERABLE_Patch_CVE_CWE'
                self.db.execute(f"""
                    UPDATE vulnerabilities
                    SET {status_col} = ?
                    WHERE COMMIT_HASH = ?
                """, (response.content, commit_hash))
                self._maybe_commit()
        elif response.raw_response and "BLOCKED" in response.raw_response:
            # Handle blocked responses
            logger.warning(f"Response blocked by safety filters for CVE/CWE check, commit_hash {commit_hash}: {response.raw_response}")
            
            # For blocked responses, we can't determine vulnerability, so mark as NULL or skip
            status_col = 'IS_VULNERABLE_Vuln_CVE_CWE' if is_vulnerable else 'IS_VULNERABLE_Patch_CVE_CWE'
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {status_col} = ?
                WHERE COMMIT_HASH = ?
            """, (None, commit_hash))  # NULL indicates blocked/unknown
            self._maybe_commit()
        else:
            logger.error(f"Failed to check specific CVE/CWE vulnerability for commit_hash {commit_hash}")
    
    def rank_cwe(self, commit_hash: str, vulnerable_code: str) -> None:
        """Rank CWEs for given vulnerable code - accepting all CWE responses without validation.
        
        Args:
            commit_hash: The commit hash
            vulnerable_code: The vulnerable code to analyze
        """
        try:
            # Keep existing prompt unchanged as requested
            prompt_template = """Analyze this vulnerable code and return EXACTLY 5 CWE identifiers as a JSON list.

Code:
{code}

Requirements:
1. Return ONLY a JSON array in this exact format: ["CWE-XXX", "CWE-YYY", "CWE-ZZZ", "CWE-AAA", "CWE-BBB"]
2. NO explanations, NO descriptions, NO additional text
3. Use only valid CWE identifiers (CWE- followed by numbers)
4. Order by likelihood (most likely first)

Response:"""
            
            # Format the prompt
            formatted_prompt = prompt_template.format(code=vulnerable_code)
            
            # Query the model
            response = self.query_model(formatted_prompt)
            
            self._log_response('rank_cwe', commit_hash, formatted_prompt, response)
            
            # Extract CWEs without strict validation - accept any format
            extracted_cwes = self._extract_cwe_ranking_without_validation(response.content)
            
            if extracted_cwes:
                # Ensure LLM_Ranked_CWE column exists
                if not self.db.column_exists("vulnerabilities", "LLM_Ranked_CWE"):
                    self.db.add_column("vulnerabilities", "LLM_Ranked_CWE TEXT")
                
                # Store in database as JSON list format
                self.db.execute(
                    "UPDATE vulnerabilities SET LLM_Ranked_CWE = ? WHERE COMMIT_HASH = ?",
                    (extracted_cwes, commit_hash)
                )
                
                self._maybe_commit()
                
                logger.info(f"✓ Ranked CWEs for commit {commit_hash[:8]}: {extracted_cwes}")
            else:
                # Store empty list if extraction fails
                logger.warning(f"No CWEs extracted, storing empty list for commit {commit_hash}: {response.content[:100]}")
                empty_cwes = '[]'
                
                # Ensure column exists
                if not self.db.column_exists("vulnerabilities", "LLM_Ranked_CWE"):
                    self.db.add_column("vulnerabilities", "LLM_Ranked_CWE TEXT")
                
                self.db.execute(
                    "UPDATE vulnerabilities SET LLM_Ranked_CWE = ? WHERE COMMIT_HASH = ?",
                    (empty_cwes, commit_hash)
                )
                
                self._maybe_commit()
                logger.info(f"✓ Stored empty CWE list for commit {commit_hash[:8]}: {empty_cwes}")
            
        except Exception as e:
            logger.error(f"Error ranking CWEs for commit {commit_hash}: {e}")
            # Even on error, store empty list to avoid NULL
            try:
                empty_cwes = '[]'
                
                if not self.db.column_exists("vulnerabilities", "LLM_Ranked_CWE"):
                    self.db.add_column("vulnerabilities", "LLM_Ranked_CWE TEXT")
                
                self.db.execute(
                    "UPDATE vulnerabilities SET LLM_Ranked_CWE = ? WHERE COMMIT_HASH = ?",
                    (empty_cwes, commit_hash)
                )
                self._maybe_commit()
                logger.info(f"✓ Used empty list for error case, commit {commit_hash[:8]}: {empty_cwes}")
            except Exception as e2:
                logger.error(f"Failed to store even empty CWE list for commit {commit_hash}: {e2}")

    def _extract_cwe_ranking_without_validation(self, output: str) -> Optional[str]:
        """Extract CWE ranking from LLM output without any validation - return as JSON list format."""
        try:
            import re
            import json
            
            # Look for JSON array pattern first
            json_match = re.search(r'\[.*?\]', output, re.DOTALL)
            if json_match:
                try:
                    cwe_list = json.loads(json_match.group())
                    if isinstance(cwe_list, list) and len(cwe_list) > 0:
                        # Accept all CWEs as-is, no validation, return as JSON list
                        cwes = [str(cwe).strip() for cwe in cwe_list]
                        return json.dumps(cwes)
                except json.JSONDecodeError:
                    pass
            
            # Fallback: extract CWE patterns
            cwe_pattern = r'CWE-(\d+)'
            matches = re.findall(cwe_pattern, output, re.IGNORECASE)
            if len(matches) > 0:
                cwes = [f'CWE-{match}' for match in matches]
                logger.debug(f"Extracted CWE patterns: {cwes}")
                return json.dumps(cwes)
            
            # Try to extract any mentions of CWE (even without numbers)
            cwe_mentions = re.findall(r'CWE[^a-zA-Z]*(\d+)', output, re.IGNORECASE)
            if len(cwe_mentions) > 0:
                cwes = [f'CWE-{match}' for match in cwe_mentions]
                logger.debug(f"Extracted CWE mentions: {cwes}")
                return json.dumps(cwes)
            
            # Try numeric extraction as last resort
            logger.debug(f"Using numeric extraction for output: {output[:100]}")
            numeric_pattern = r'\b(\d{1,4})\b'
            numbers = re.findall(numeric_pattern, output)
            if len(numbers) > 0:
                cwes = [f'CWE-{num}' for num in numbers[:10]]  # Limit to prevent too many
                logger.debug(f"Using numeric extraction: {cwes}")
                return json.dumps(cwes)
            
            logger.warning(f"Could not extract any CWE identifiers from: {output[:100]}")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting CWE ranking: {e}")
            return None

    def run_single_task(self, task_name: str, database_path: str = None) -> None:
        """Run a single task on the database to fill gaps.
        
        Args:
            task_name: Name of the task to run ('vuln', 'patch', 'vuln_cve_cwe', 'patch_cve_cwe', 'rank_cwe', 'all')
            database_path: Optional database path (uses current if not specified)
        """
        if database_path and database_path != str(self.db_file):
            # Reinitialize with new database
            from utils.database import Database
            self.db = Database(database_path)
            self.db_file = Path(database_path)
            self.create_columns()
        
        valid_tasks = ['vuln', 'patch', 'vuln_cve_cwe', 'patch_cve_cwe', 'rank_cwe', 'all']
        
        if task_name not in valid_tasks:
            logger.error(f"Invalid task: {task_name}. Valid tasks: {valid_tasks}")
            return
        
        if task_name == 'all':
            self.analyze_and_fill_database_gaps()
        else:
            # Get all records to analyze
            records = self.db.execute("""
                SELECT COMMIT_HASH, VULNERABLE_CODE_BLOCK, PATCHED_CODE_BLOCK, 
                       VULNERABILITY_CVE, VULNERABILITY_CWE, DESCRIPTION_IN_PATCH,
                       IS_VULNERABLE_Vuln, IS_VULNERABLE_Patch, 
                       IS_VULNERABLE_Vuln_CVE_CWE, IS_VULNERABLE_Patch_CVE_CWE,
                       LLM_Ranked_CWE
                FROM vulnerabilities
                WHERE VULNERABLE_CODE_BLOCK IS NOT NULL AND VULNERABLE_CODE_BLOCK != ''
            """).fetchall()
            
            if not records:
                logger.warning("No records found with vulnerable code blocks")
                return
            
            total_records = len(records)
            logger.info(f"Found {total_records} records to analyze for task: {task_name}")
            
            # Track statistics
            filled_count = 0
            
            for i, record in enumerate(records, 1):
                commit_hash = record[0]
                vulnerable_code = record[1]
                patched_code = record[2]
                cve = record[3]
                cwe = record[4]
                description = record[5]
                
                # Process based on task type
                should_process = False
                
                if task_name == 'vuln' and record[6] is None:
                    logger.info(f"[{i}/{total_records}] Checking vulnerability status for vulnerable code: {commit_hash[:8]}")
                    self.is_vulnerable_func(commit_hash, vulnerable_code, is_vulnerable=True)
                    should_process = True
                
                elif task_name == 'patch' and record[7] is None and patched_code:
                    logger.info(f"[{i}/{total_records}] Checking vulnerability status for patched code: {commit_hash[:8]}")
                    self.is_vulnerable_func(commit_hash, patched_code, is_vulnerable=False)
                    should_process = True
                
                elif task_name == 'vuln_cve_cwe' and record[8] is None and cve and cwe:
                    logger.info(f"[{i}/{total_records}] Checking CVE/CWE vulnerability for vulnerable code: {commit_hash[:8]}")
                    self.is_vulnerable_to_CVE_CWE(commit_hash, vulnerable_code, cve, cwe, is_vulnerable=True)
                    should_process = True
                
                elif task_name == 'patch_cve_cwe' and record[9] is None and patched_code and cve and cwe:
                    logger.info(f"[{i}/{total_records}] Checking CVE/CWE vulnerability for patched code: {commit_hash[:8]}")
                    self.is_vulnerable_to_CVE_CWE(commit_hash, patched_code, cve, cwe, is_vulnerable=False)
                    should_process = True
                
                elif task_name == 'rank_cwe' and not record[10]:
                    logger.info(f"[{i}/{total_records}] Ranking CWEs: {commit_hash[:8]}")
                    self.rank_cwe(commit_hash, vulnerable_code)
                    should_process = True
                
                if should_process:
                    filled_count += 1
                
                # Progress indicator
                if i % 50 == 0:
                    logger.info(f"Progress: {i}/{total_records} records processed")
            
            # Final commit
            self.flush_commits()
            
            logger.info(f"Task '{task_name}' completed! Filled {filled_count} records.")
    
    def _calculate_gemma_probability_safe(self, prompt: str, generated_text: str) -> Optional[float]:
        """Calculate probability for Gemma using GPU-only safe method that avoids CUDA assertion errors.
        
        Args:
            prompt: The input prompt
            generated_text: The generated response text
            
        Returns:
            Estimated probability or None if calculation fails
        """
        try:
            import torch
            import torch.nn.functional as F
            
            # Ensure we have pipeline access
            if not self.pipeline:
                logger.warning("No pipeline available for Gemma probability calculation")
                return None
            
            tokenizer = self.pipeline.tokenizer
            model = self.pipeline.model
            
            # Keep everything on GPU - no CPU transfer
            device = next(model.parameters()).device
            
            # Tokenize the sequences
            prompt_ids = tokenizer.encode(prompt, return_tensors='pt', truncation=True, max_length=512).to(device)
            full_text = prompt + generated_text
            full_ids = tokenizer.encode(full_text, return_tensors='pt', truncation=True, max_length=512).to(device)
            
            # Find generated tokens
            prompt_length = prompt_ids.shape[1]
            if full_ids.shape[1] <= prompt_length:
                logger.warning("No generated tokens found for probability calculation")
                return None
            
            generated_ids = full_ids[0, prompt_length:]
            
            with torch.no_grad():
                # Use a different approach: run inference without output_scores
                # Then manually compute logits for each token position
                
                try:
                    # Get logits for the full sequence using standard forward pass
                    model_outputs = model(full_ids, return_dict=True, use_cache=False)
                    logits = model_outputs.logits
                    
                    # Extract probabilities using a safer method
                    token_probs = []
                    
                    # Process each generated token position
                    for i, target_token in enumerate(generated_ids):
                        if prompt_length + i - 1 < logits.shape[1]:
                            # Get logits for position that predicts this token
                            position_logits = logits[0, prompt_length + i - 1]
                            
                            # Apply temperature to make probabilities more stable
                            temperature = 2.0  # Higher temperature for stability
                            scaled_logits = position_logits / temperature
                            
                            # Clamp logits to prevent extreme values
                            clamped_logits = torch.clamp(scaled_logits, min=-50, max=50)
                            
                            # Use log_softmax instead of softmax for numerical stability
                            log_probs = F.log_softmax(clamped_logits, dim=-1)
                            
                            # Get log probability for the target token
                            if target_token < log_probs.shape[0]:
                                token_log_prob = log_probs[target_token].item()
                                
                                # Convert to probability (but keep in log space for stability)
                                if not (torch.isnan(torch.tensor(token_log_prob)) or 
                                       torch.isinf(torch.tensor(token_log_prob))):
                                    token_probs.append(token_log_prob)
                    
                    if token_probs:
                        # Calculate average log probability, then convert to probability
                        avg_log_prob = sum(token_probs) / len(token_probs)
                        # Convert back to probability space
                        avg_prob = min(max(torch.exp(torch.tensor(avg_log_prob)).item(), 1e-8), 1.0)
                        
                        logger.debug(f"Calculated Gemma probability (GPU-only): {avg_prob:.4f} from {len(token_probs)} tokens")
                        return avg_prob
                    else:
                        logger.warning("No valid probabilities calculated for Gemma")
                        return None
                        
                except Exception as calc_e:
                    logger.warning(f"GPU probability calculation failed for Gemma: {calc_e}")
                    
                    # Fallback: estimate probability based on response length and complexity
                    try:
                        # Simple heuristic: shorter, more common responses get higher probability
                        response_length = len(generated_text.strip())
                        
                        # Basic responses (like "1", "0", "yes", "no") get high probability
                        if response_length <= 10 and generated_text.strip().lower() in ['1', '0', 'yes', 'no', 'true', 'false']:
                            estimated_prob = 0.85
                        elif response_length <= 20:
                            estimated_prob = 0.70
                        elif response_length <= 50:
                            estimated_prob = 0.60
                        else:
                            estimated_prob = 0.45
                        
                        logger.debug(f"Using heuristic probability for Gemma: {estimated_prob:.2f}")
                        return estimated_prob
                        
                    except Exception as fallback_e:
                        logger.error(f"Even heuristic probability calculation failed: {fallback_e}")
                        return None
                    
        except Exception as e:
            logger.error(f"GPU-only probability calculation failed for Gemma: {e}")
            return None

    # ...existing methods...
