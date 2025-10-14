"""Module for interacting with LLMs for vulnerability evaluation."""

import logging
import json
import re
import time
from pathlib import Path
import requests
from typing import List, Dict, Any, Optional, Union, Tuple
import shutil

from utils.database import Database
from utils.logger import setup_logger

logger = logging.getLogger(__name__)

class LLMInteraction:
    """Class for interacting with LLMs to evaluate vulnerabilities."""
    
    def __init__(
        self, 
        db_file: Union[str, Path], 
        model_name: str, 
        api_url: str = "http://localhost:11434/api/generate",
        api_param: Optional[str] = None
    ):
        """Initialize the LLM interaction.
        
        Args:
            db_file: Path to the SQLite database
            model_name: Name of the LLM to use
            api_url: URL for the LLM API
            api_param: Parameter name for the LLM API (defaults to model_name)
        """
        self.db_file = Path(db_file)
        self.model_name = model_name
        self.api_url = api_url
        self.api_param = api_param or model_name
        self.db = Database(self.db_file)
        
        # Create necessary columns in the database
        self.create_columns()
        
        logger.info(f"Initialized LLMInteraction with model: {model_name}")
    
    def create_columns(self) -> None:
        """Create necessary columns in the database if they do not exist."""
        columns = [          
            "LLM_Ranked_CVE TEXT",
            "LLM_Ranked_CWE TEXT",
            "IS_VULNERABLE_Vuln INT",
            "IS_VULNERABLE_Patch INT",
            "IS_VULNERABLE_Vuln_CVE_CWE INT",
            "IS_VULNERABLE_Patch_CVE_CWE INT",
            "Patched_Block_LLM TEXT",
            "Patched_Block_LLM_F TEXT",
            "LLM_Ranked_CVE_F TEXT",
            "LLM_Ranked_CWE_F TEXT",
            "CVE_Vuln INT",
            "CVE_Patch INT",
            "CWE_Vuln INT",
            "CWE_Patch INT",
            "CVE_Vuln_F INT",
            "CVE_Patch_F INT",
            "CWE_Vuln_F INT",
            "CWE_Patch_F INT",
            "CVE_CWE_Vuln INT",
            "CVE_CWE_Patch INT",
            "CVE_CWE_Vuln_F INT", 
            "CVE_CWE_Patch_F INT",
            "NUM_LINES_IN_PATCHED_BLOCK_LLM INT",
            "NUM_LINES_IN_PATCHED_BLOCK_LLM_F INT"
        ]
        
        for column_def in columns:
            column_name = column_def.split()[0]
            self.db.add_column("vulnerabilities", column_def)
    
    def query_model(self, prompt: str, max_retries: int = 3, retry_delay: int = 2) -> Optional[str]:
        """Sends a prompt to the model and retrieves the generated response.
        
        Args:
            prompt: The prompt to send to the model
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            
        Returns:
            Generated response or None if failed
        """
        payload = {
            "model": self.api_param,
            "prompt": prompt,
            "temperature": 1.0
        }

        for attempt in range(max_retries):
            try:
                response = requests.post(self.api_url, json=payload)
                if response.status_code == 200:
                    response_lines = response.content.decode('utf-8').splitlines()
                    full_response = ''.join([json.loads(line)["response"] for line in response_lines if line])
                    if full_response == "":
                        logger.warning("Empty response. Retrying...")
                        time.sleep(retry_delay)
                        continue
                    return full_response
                elif response.status_code == 503:
                    wait_time = retry_delay * (attempt + 1)
                    logger.warning(f"Model is loading, retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"HTTP Error {response.status_code}: {response.text}")
                    if attempt < max_retries - 1:
                        logger.info("Retrying...")
                    else:
                        logger.error("Reached maximum retry attempts.")
                    time.sleep(retry_delay)
            except requests.RequestException as e:
                logger.error(f"Request exception: {e}")
                time.sleep(retry_delay)

        return None
    
    def extract_vulnerability_names(self, text: str) -> Tuple[List[str], List[str]]:
        """Extract CVE and CWE names from the LLM response.
        
        Args:
            text: LLM response text
            
        Returns:
            Tuple with lists of CVE and CWE names
        """
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cwe_pattern = r"CWE-\d{1,4}"
        cve_names = re.findall(cve_pattern, text)
        cwe_names = re.findall(cwe_pattern, text)
        return cve_names, cwe_names
    
    def rank_cve(self, commit_hash: str, vulnerable_code_block: str, vulnerability_year: str, 
                 description: Optional[str] = None, few_shot: bool = False) -> None:
        """Rank the top 5 most likely CVEs for the provided C code snippets by probability.
        
        Args:
            commit_hash: Git commit hash
            vulnerable_code_block: Vulnerable code block text
            vulnerability_year: Year of the vulnerability
            description: Description of the vulnerability (for few-shot learning)
            few_shot: Whether to use few-shot learning
        """
        if few_shot:
            prompt_cve = (
                f"Identify the five most likely CVEs (Common Vulnerabilities and Exposures) "
                f"for the provided C code snippets from the year {vulnerability_year}. Description: {description}. "
                f"Provide the CVE names ordered by their likelihood, without any additional information or duplication. "
                f"CVE pattern: CVE-YYYY-XXXX."
            )
            column_name = 'LLM_Ranked_CVE_F'
        else:
            prompt_cve = (
                f"Identify the five most likely CVEs (Common Vulnerabilities and Exposures) "
                f"for the provided C code snippets from the year {vulnerability_year}. "
                f"Provide the CVE names ordered by their likelihood, without any additional information or duplication. "
                f"CVE pattern: CVE-YYYY-XXXX."
            )
            column_name = 'LLM_Ranked_CVE'
            
        prompt_cve += f"\n{vulnerable_code_block}"
        
        result_cve = self.query_model(prompt_cve)
        
        if result_cve:
            cve_list = self.extract_vulnerability_names(result_cve)[0]
            if not cve_list:
                cve_list = [result_cve]
            
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (json.dumps(cve_list), commit_hash))
            self.db.commit()
            logger.info(f"Ranked CVEs updated for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to rank CVEs for commit_hash {commit_hash}")

    def rank_cwe(self, commit_hash: str, vulnerable_code_block: str, 
                 description: Optional[str] = None, few_shot: bool = False) -> None:
        """Rank the top 5 most likely CWEs for the provided C code snippets by probability.
        
        Args:
            commit_hash: Git commit hash
            vulnerable_code_block: Vulnerable code block text
            description: Description of the vulnerability (for few-shot learning)
            few_shot: Whether to use few-shot learning
        """
        if few_shot:
            prompt_cwe = (
                f"Identify the five most likely CWEs (Common Weakness Enumeration) "
                f"for the provided C code snippets. Description: {description}. "
                f"Provide the CWE names ordered by their likelihood, without any additional information or duplication. "
                f"CWE pattern: CWE-XXX."
            )
            column_name = 'LLM_Ranked_CWE_F'
        else:
            prompt_cwe = (
                f"Identify the five most likely CWEs (Common Weakness Enumeration) "
                f"for the provided C code snippets. "
                f"Provide the CWE names ordered by their likelihood, without any additional information or duplication. "
                f"CWE pattern: CWE-XXX."
            )
            column_name = 'LLM_Ranked_CWE'
            
        prompt_cwe += f"\n{vulnerable_code_block}"
        
        result_cwe = self.query_model(prompt_cwe)
        
        if result_cwe:
            cwe_list = self.extract_vulnerability_names(result_cwe)[1]
            if not cwe_list:
                cwe_list = [result_cwe]
                
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (json.dumps(cwe_list), commit_hash))
            self.db.commit()
            logger.info(f"Ranked CWEs updated for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to rank CWEs for commit_hash {commit_hash}")
    
    def cve_vuln_patch(self, commit_hash: str, code_block: str, 
                       description: Optional[str] = None, few_shot: bool = False, 
                       is_vulnerable: bool = True) -> None:
        """Check if the code block has a specific CVE and update the result in the database.
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            description: Description of the vulnerability (for few-shot learning)
            few_shot: Whether to use few-shot learning
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
        """
        if few_shot:
            prompt = (
                f"Check if the following C code block has a specific CVE vulnerability. "
                f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                f"Description: {description}\n code block:{code_block}"
            )
            column_name = 'CVE_Vuln_F' if is_vulnerable else 'CVE_Patch_F'
        else:
            prompt = (
                f"Check if the following C code block has a specific CVE vulnerability. "
                f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                f"code block: {code_block}"
            )
            column_name = 'CVE_Vuln' if is_vulnerable else 'CVE_Patch'
        
        result = self.query_model(prompt)
        
        if result:
            status = self._parse_vulnerability_response(result)
            
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status if status is not None else result, commit_hash))
            self.db.commit()
            
            if status is not None:
                logger.info(f"CVE vulnerability check result ({status}) updated for commit_hash {commit_hash}")
            else:
                logger.warning(f"Unclear CVE vulnerability check result for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to check CVE vulnerability for commit_hash {commit_hash}")
  
    def cwe_vuln_patch(self, commit_hash: str, code_block: str, 
                       description: Optional[str] = None, few_shot: bool = False, 
                       is_vulnerable: bool = True) -> None:
        """Check if the code block has a specific CWE and update the result in the database.
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            description: Description of the vulnerability (for few-shot learning)
            few_shot: Whether to use few-shot learning
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
        """
        if few_shot:
            prompt = (
                f"Check if the following C code block has a specific CWE vulnerability. "
                f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                f"Description: {description}\n code block:{code_block}"
            )
            column_name = 'CWE_Vuln_F' if is_vulnerable else 'CWE_Patch_F'
        else:
            prompt = (
                f"Check if the following C code block has a specific CWE vulnerability. "
                f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                f"code block:{code_block}"
            )
            column_name = 'CWE_Vuln' if is_vulnerable else 'CWE_Patch'
    
        result = self.query_model(prompt)
        
        if result:
            status = self._parse_vulnerability_response(result)
            
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status if status is not None else result, commit_hash))
            self.db.commit()
            
            if status is not None:
                logger.info(f"CWE vulnerability check result ({status}) updated for commit_hash {commit_hash}")
            else:
                logger.warning(f"Unclear CWE vulnerability check result for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to check CWE vulnerability for commit_hash {commit_hash}")
    
    def check_cve_cwe_vulnerability(self, commit_hash: str, code_block: str, 
                                   cve: Optional[str] = None, cwe: Optional[str] = None, 
                                   description: Optional[str] = None, few_shot: bool = False, 
                                   is_vulnerable: bool = True) -> None:
        """Check if the given code block has a vulnerability related to specific CVE and CWE.
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            cve: Specific CVE (optional)
            cwe: Specific CWE (optional)
            description: Description of the vulnerability (for few-shot learning)
            few_shot: Whether to use few-shot learning
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
        """
        cve_text = f"CVE: {cve}" if cve else "CVE"
        cwe_text = f"CWE: {cwe}" if cwe else "CWE"
        
        if few_shot:
            prompt = (
                f"Does the following C code have a vulnerability associated with {cve_text} and {cwe_text}? "
                f"Description: {description}. Respond with '1' if it has a vulnerability, otherwise respond with '0'.\n"
                f"Code block:\n{code_block}"
            )
            column_name = 'CVE_CWE_Vuln_F' if is_vulnerable else 'CVE_CWE_Patch_F'
        else:
            prompt = (
                f"Does the following C code have a vulnerability associated with {cve_text} and {cwe_text}? "
                f"Respond with '1' if it has a vulnerability, otherwise respond with '0'.\n"
                f"Code block:\n{code_block}"
            )
            column_name = 'CVE_CWE_Vuln' if is_vulnerable else 'CVE_CWE_Patch'
                
        result = self.query_model(prompt)
        
        if result:
            status = self._parse_vulnerability_response(result)
            
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status if status is not None else result, commit_hash))
            self.db.commit()
            
            if status is not None:
                logger.info(f"CVE/CWE vulnerability check result ({status}) updated for commit_hash {commit_hash}")
            else:
                logger.warning(f"Unclear CVE/CWE vulnerability check result for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to check CVE/CWE vulnerability for commit_hash {commit_hash}")

    def update_code_block_llm(self, commit_hash: str, code: str, few_shot: bool = False) -> None:
        """Update the code block generated by LLM.
        
        Args:
            commit_hash: Git commit hash
            code: Generated code block
            few_shot: Whether using few-shot learning
        """
        column_name = 'Patched_Block_LLM_F' if few_shot else 'Patched_Block_LLM'
        
        self.db.execute(f"""
            UPDATE vulnerabilities
            SET {column_name} = ?
            WHERE COMMIT_HASH = ?
        """, (code, commit_hash))
        self.db.commit()
        logger.info(f"Updated LLM-generated code block for commit_hash {commit_hash}")

    def suggest_a_fix(self, commit_hash: str, vulnerable_code_block: str, cve: str, cwe: str, 
                     description: Optional[str] = None, few_shot: bool = False) -> None:
        """Generate a fix for the vulnerable code block.
        
        Args:
            commit_hash: Git commit hash
            vulnerable_code_block: Vulnerable code block text
            cve: CVE identifier
            cwe: CWE identifier
            description: Description of the vulnerability (for few-shot learning)
            few_shot: Whether to use few-shot learning
        """
        if few_shot:
            prompt = (
                f"Please correct the following vulnerable C code to fix the security issue without changing its functionality. "
                f"Description of changes: {description}. "
                f"Provide the entire fixed code in the specified format, including all necessary parts. "
                f"Do not use ellipses or leave any parts of the code out.\n"
                f"Format example:\n"
                f"// File path: path/to/file1\nUpdated non-function element 1\n\n"
                f"// File path: path/to/file2\nUpdated Function 1(int param1, char *param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"// File path: path/to/file3\nUpdated non-function element 2\n\n"
                f"// File path: path/to/file4\nUpdated Function 2(double param1, int param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"This C code block is a vulnerability identified as {cve} and has the weaknesses of {cwe}.\n"
                f"Here is the vulnerable code:\n{vulnerable_code_block}"
            )
        else:
            prompt = (
                f"Please correct the following vulnerable C code to fix the security issue without changing its functionality. "
                f"Provide the entire fixed code in the specified format, including all necessary parts. "
                f"Do not use ellipses or leave any parts of the code out.\n"
                f"Format example:\n"
                f"// File path: path/to/file1\nUpdated non-function element 1\n\n"
                f"// File path: path/to/file2\nUpdated Function 1(int param1, char *param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"// File path: path/to/file3\nUpdated non-function element 2\n\n"
                f"// File path: path/to/file4\nUpdated Function 2(double param1, int param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"Here is the vulnerable code:\n{vulnerable_code_block}"
            )
        
        result = self.query_model(prompt)
        if result:
            code_block = re.findall(r'```(?:\w+)?\n(.*?)```', result, re.DOTALL)
            if code_block:
                res = "\n\n".join(code_block)
            else:
                # If no code blocks found, use the whole result
                res = result
                
            self.update_code_block_llm(commit_hash, res, few_shot)
            logger.info(f"Fix suggested for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to generate a fix for commit_hash {commit_hash}")
    
    def is_vulnerable_func(self, commit_hash: str, code_block: str, is_vulnerable: bool = True) -> None:
        """Check if the code block is vulnerable or not (Zero-shot).
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
        """
        prompt = (
            f"Check if the following C code block is vulnerable. "
            f"Respond with '1' if it is vulnerable, otherwise respond with '0'.\n"
            f"code block:{code_block}"
        )
        column_name = 'IS_VULNERABLE_Vuln' if is_vulnerable else 'IS_VULNERABLE_Patch'
        
        result = self.query_model(prompt)
        if result:
            status = self._parse_vulnerability_response(result)
            
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status if status is not None else result, commit_hash))
            self.db.commit()
            
            if status is not None:
                logger.info(f"Vulnerability check result ({status}) updated for commit_hash {commit_hash}")
            else:
                logger.warning(f"Unclear vulnerability check result for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to check vulnerability for commit_hash {commit_hash}")
            
    def is_vulnerable_to_CVE_CWE(self, commit_hash: str, code_block: str, cve: str, cwe: str, 
                                is_vulnerable: bool = True) -> None:
        """Check if the code block is vulnerable to a specific CVE/CWE (Zero-shot).
        
        Args:
            commit_hash: Git commit hash
            code_block: Code block to check
            cve: CVE identifier
            cwe: CWE identifier
            is_vulnerable: Whether checking for vulnerable code (True) or patched code (False)
        """
        prompt = (
            f"Check if the following C code block is vulnerable to the specific CVE ({cve}) and CWE ({cwe}). "
            f"Respond with '1' if it is vulnerable, otherwise respond with '0'.\n"
            f"code block:{code_block}"
        )
        column_name = 'IS_VULNERABLE_Vuln_CVE_CWE' if is_vulnerable else 'IS_VULNERABLE_Patch_CVE_CWE'
        
        result = self.query_model(prompt)
        if result:
            status = self._parse_vulnerability_response(result)
            
            self.db.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status if status is not None else result, commit_hash))
            self.db.commit()
            
            if status is not None:
                logger.info(f"Specific CVE/CWE vulnerability check result ({status}) updated for commit_hash {commit_hash}")
            else:
                logger.warning(f"Unclear specific CVE/CWE vulnerability check result for commit_hash {commit_hash}")
        else:
            logger.error(f"Failed to check specific CVE/CWE vulnerability for commit_hash {commit_hash}")
    
    def update_line_counts(self) -> None:
        """Update the number of lines in the LLM-generated code blocks."""
        try:
            # Add the columns if they don't exist
            for column in ['NUM_LINES_IN_PATCHED_BLOCK_LLM', 'NUM_LINES_IN_PATCHED_BLOCK_LLM_F']:
                self.db.add_column("vulnerabilities", f"{column} INTEGER")
            
            # Update regular patched blocks
            self.db.execute("""
            UPDATE vulnerabilities 
            SET NUM_LINES_IN_PATCHED_BLOCK_LLM = (LENGTH(Patched_Block_LLM) - LENGTH(REPLACE(Patched_Block_LLM, '\n', '')) + 1)
            WHERE Patched_Block_LLM IS NOT NULL
            """)
            
            # Update few-shot patched blocks
            self.db.execute("""
            UPDATE vulnerabilities 
            SET NUM_LINES_IN_PATCHED_BLOCK_LLM_F = (LENGTH(Patched_Block_LLM_F) - LENGTH(REPLACE(Patched_Block_LLM_F, '\n', '')) + 1)
            WHERE Patched_Block_LLM_F IS NOT NULL
            """)
            
            self.db.commit()
            logger.info("Updated line counts for LLM-generated code blocks")
        except Exception as e:
            logger.error(f"Error updating line counts: {e}")
            raise
            
    def _parse_vulnerability_response(self, result: str) -> Optional[int]:
        """Parse the LLM response to determine vulnerability status.
        
        Args:
            result: LLM response text
            
        Returns:
            1 if vulnerable, 0 if not vulnerable, None if unclear
        """
        # Positive indicators
        if (re.search(r'\b1\b', result) or 
            'yes' in result.lower() or 
            'has a vulnerability' in result.lower() or 
            'is vulnerable' in result.lower() or 
            'contains a vulnerability' in result.lower() or 
            'has a security issue' in result.lower() or 
            'has a security vulnerability' in result.lower() or 
            'has a security flaw' in result.lower() or 
            'the code block has the' in result.lower() or 
            'the code block contains the' in result.lower() or 
            'found a vulnerability' in result.lower() or 
            'vulnerability associated with' in result.lower() or 
            'is vulnerable to' in result.lower() or 
            'found a potential vulnerability' in result.lower() or 
            'it appears to be vulnerable to' in result.lower() or 
            'code appears to be vulnerable to' in result.lower() or 
            'I can identify a potential vulnerability' in result.lower() or 
            'code block has a specific' in result.lower() or 
            'code block has the vulnerability' in result.lower() or 
            'code block appears to be vulnerable' in result.lower() or 
            'code block you provided has the' in result.lower() or 
            'code block appears to have a vulnerability' in result.lower()):
            return 1
        
        # Negative indicators
        elif (re.search(r'\b0\b', result) or 
              'no' in result.lower() or 
              'does not have a vulnerability' in result.lower() or 
              'does not contain' in result.lower() or 
              'is not vulnerable' in result.lower() or 
              'does not have a security issue' in result.lower() or 
              'does not have a security vulnerability' in result.lower() or 
              'does not have a security flaw' in result.lower() or 
              'the code block does not have the' in result.lower() or 
              'the code block does not contain the' in result.lower() or 
              'the code block does not have a' in result.lower() or 
              'the code block does not contain a' in result.lower() or 
              'the code block does not have an' in result.lower() or 
              'the code block does not contain an' in result.lower() or 
              'the code block does not have any' in result.lower() or 
              'the code block does not contain any' in result.lower() or 
              "it doesn't appear to have a specific" in result.lower()):
            return 0
        
        # Unclear response
        else:
            return None 