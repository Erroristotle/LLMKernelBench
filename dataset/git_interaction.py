"""Git interaction utilities for analyzing vulnerability commits."""

import subprocess
import re
import os
import requests
import logging
from typing import Dict, List, Optional, Tuple, Union, Any

logger = logging.getLogger(__name__)

class GitInteraction:
    """Class for interacting with Git repositories and analyzing code changes."""
    
    def __init__(self, repo_path: str):
        """Initialize with repository path.
        
        Args:
            repo_path: Path to the Git repository
        """
        self.repo_path = repo_path
        logger.debug(f"Initialized GitInteraction with repo path: {repo_path}")

    def get_file_at_commit(self, commit_hash: str, file_path: str) -> Optional[str]:
        """Get the contents of a file at a specific commit.
        
        Args:
            commit_hash: Git commit hash
            file_path: Path to the file within the repository
            
        Returns:
            File contents as string or None if error occurred
        """
        try:
            command = ["git", "show", f"{commit_hash}:{file_path}"]
            result = subprocess.run(
                command, 
                cwd=self.repo_path, 
                text=True, 
                capture_output=True, 
                check=True, 
                encoding='utf-8', 
                errors='ignore'
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting file at commit: {commit_hash}, file: {file_path}")
            logger.debug(f"Error details: {e.output}")
            return None

    def get_patch_of_commit(self, commit_hash: str) -> Optional[str]:
        """Fetch the patch of a specific commit from the GitHub URL.
        
        Args:
            commit_hash: Git commit hash
            
        Returns:
            Patch text or None if error occurred
        """
        url = f"https://github.com/torvalds/linux/commit/{commit_hash}.patch"
        try:
            response = requests.get(url)
            response.raise_for_status()
            patch_text = response.text
            return patch_text
        except requests.RequestException as e:
            logger.error(f"Error fetching patch from URL: {url}")
            logger.debug(f"Error details: {e}")
            return None

    def fetch_pre_fix_vulnerable_code(self, commit_hash: str, file_path: str) -> Optional[str]:
        """Fetch vulnerable code segments from the commit prior to the fixing commit.
        
        Args:
            commit_hash: Git commit hash
            file_path: Path to the file
            
        Returns:
            Vulnerable code or None if error occurred
        """
        parent_commit_hash = f"{commit_hash}^"
        return self.get_file_at_commit(parent_commit_hash, file_path)

    def fetch_fixed_code(self, commit_hash: str, file_path: str) -> Optional[str]:
        """Fetch patched code segments from the commit.
        
        Args:
            commit_hash: Git commit hash
            file_path: Path to the file
            
        Returns:
            Fixed code or None if error occurred
        """
        return self.get_file_at_commit(commit_hash, file_path)    
    
    def extract_function_signatures(self, code: str) -> List[str]:
        """Extract function signatures from the code.
        
        Args:
            code: C code string
            
        Returns:
            List of function signatures
        """
        if not isinstance(code, str):
            return []
            
        pattern = r'\b(?:(?:static|struct\s+\w+\s*\*?)\s+)*\w+\s+\**\w+\s*\([^)]*\)\s*\{'
        matches = re.findall(pattern, code, re.MULTILINE)
        function_signatures = [match.strip() for match in matches]
        return function_signatures
    
    def extract_files_and_functions_info(self, patch_text: str) -> Dict[str, Dict[str, Any]]:
        """Extract the file paths and function names that contain added or deleted lines from a diff.
        
        Args:
            patch_text: Git patch text
            
        Returns:
            Structured dictionary with file and function information
        """
        function_pattern = re.compile(r'^@@.*?@@\s*(\w[\w\s\*]*)\(')
        file_path_pattern = re.compile(r'^diff --git a/(.*?) b/')

        files_info = {}
        current_function = None
        current_file_path = None
        current_added_block = []
        current_deleted_block = []
        lines = patch_text.split('\n')

        for line in lines:
            file_match = file_path_pattern.search(line)
            if file_match:
                current_file_path = file_match.group(1).strip()
                if current_file_path not in files_info:
                    files_info[current_file_path] = {'functions': {}}
                current_function = None  # Reset current function context when encountering a new file path
                continue

            match = function_pattern.search(line)
            if match:
                current_function = match.group(1).strip()
                if current_function not in files_info[current_file_path]['functions']:
                    files_info[current_file_path]['functions'][current_function] = {'added': [], 'deleted': []}
                # Clear the current blocks when encountering a new function
                current_added_block = []
                current_deleted_block = []
            else:
                if current_file_path:
                    if line.startswith('+') and not line.startswith('+++'):
                        if current_deleted_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['deleted'].append(
                                    '\n'.join(current_deleted_block)
                                )
                            else:
                                if 'deleted' not in files_info[current_file_path]:
                                    files_info[current_file_path]['deleted'] = []
                                files_info[current_file_path]['deleted'].append('\n'.join(current_deleted_block))
                            current_deleted_block = []
                        current_added_block.append(line[1:].strip())
                    elif line.startswith('-') and not line.startswith('---'):
                        if current_added_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['added'].append(
                                    '\n'.join(current_added_block)
                                )
                            else:
                                if 'added' not in files_info[current_file_path]:
                                    files_info[current_file_path]['added'] = []
                                files_info[current_file_path]['added'].append('\n'.join(current_added_block))
                            current_added_block = []
                        current_deleted_block.append(line[1:].strip())
                    else:
                        if current_added_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['added'].append(
                                    '\n'.join(current_added_block)
                                )
                            else:
                                if 'added' not in files_info[current_file_path]:
                                    files_info[current_file_path]['added'] = []
                                files_info[current_file_path]['added'].append('\n'.join(current_added_block))
                            current_added_block = []
                        if current_deleted_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['deleted'].append(
                                    '\n'.join(current_deleted_block)
                                )
                            else:
                                if 'deleted' not in files_info[current_file_path]:
                                    files_info[current_file_path]['deleted'] = []
                                files_info[current_file_path]['deleted'].append('\n'.join(current_deleted_block))
                            current_deleted_block = []

        # Add any remaining blocks after the loop ends 
        if current_added_block and current_file_path:
            if current_function:
                files_info[current_file_path]['functions'][current_function]['added'].append('\n'.join(current_added_block))
            else:
                if 'added' not in files_info[current_file_path]:
                    files_info[current_file_path]['added'] = []
                files_info[current_file_path]['added'].append('\n'.join(current_added_block))
        if current_deleted_block and current_file_path:
            if current_function:
                files_info[current_file_path]['functions'][current_function]['deleted'].append('\n'.join(current_deleted_block))
            else:
                if 'deleted' not in files_info[current_file_path]:
                    files_info[current_file_path]['deleted'] = []
                files_info[current_file_path]['deleted'].append('\n'.join(current_deleted_block))

        # Remove empty strings from the added and deleted lines
        for file_path, changes in files_info.items():
            if 'added' in changes:
                changes['added'] = list(filter(None, changes['added']))
            if 'deleted' in changes:
                changes['deleted'] = list(filter(None, changes['deleted']))
            
            functions_to_remove = []
            for function_name, function_changes in changes['functions'].items():
                function_changes['added'] = list(filter(None, function_changes['added']))
                function_changes['deleted'] = list(filter(None, function_changes['deleted']))
                
                # Mark empty function names for removal
                if not function_name:
                    functions_to_remove.append(function_name)
            
            # Remove empty function names
            for func_name in functions_to_remove:
                del changes['functions'][func_name]

        return files_info

    def extract_function(self, code: str, function_name: str) -> Optional[str]:
        """Extract the entire vulnerable/patched function version of a specific function.
        
        Args:
            code: Source code string
            function_name: Name of the function to extract
            
        Returns:
            Extracted function or None if not found
        """
        if not isinstance(code, str):
            return None
        
        function_start_pattern = re.compile(r'\b{}\b\s*\([^{{}}]*\)\s*{{'.format(re.escape(function_name)), re.DOTALL)
        match = function_start_pattern.search(code)
        
        if not match:
            return None
        
        start_index = match.start()
        
        brace_stack = []
        inside_function = False
        end_index = start_index
        
        for i in range(start_index, len(code)):
            if code[i] == '{':
                brace_stack.append('{')
                inside_function = True
            elif code[i] == '}':
                if brace_stack:
                    brace_stack.pop()
                    if not brace_stack:
                        end_index = i + 1
                        break
        
        if not inside_function or brace_stack:
            return None
        
        function = code[start_index:end_index]
        return function
    
    def is_change_within_function(self, function: str, changes: Dict[str, List[str]]) -> bool:
        """Check if any change blocks are within the function.
        
        Args:
            function: Function source code
            changes: Dictionary with 'added' and 'deleted' lists
            
        Returns:
            True if changes are within the function, False otherwise
        """
        function_lines = function.split('\n')
        change_blocks = changes['added'] + changes['deleted']
    
        for change in change_blocks:
            change_lines = change.split('\n')
            change_lines = [line.strip() for line in change_lines if line.strip()]
            
            if not change_lines:
                continue
    
            for i in range(len(function_lines) - len(change_lines) + 1):
                match = True
                for j in range(len(change_lines)):
                    if change_lines[j] != function_lines[i + j].strip():
                        match = False
                        break
                if match:
                    return True
        return False
     
    def parse_patch_header(self, patch_text: str) -> Tuple[int, int, int]:
        """Parse the patch header to extract the number of files changed, added, and deleted lines.
        
        Args:
            patch_text: Git patch text
            
        Returns:
            Tuple containing (files_changed, added_lines, deleted_lines)
        """
        added_lines = 0
        deleted_lines = 0
        files_changed = set()
        
        file_pattern = re.compile(r'^diff --git a/(.*?) b/(.*?)$', re.MULTILINE)
        # find all the files changed in the diff
        matches = file_pattern.findall(patch_text)
        for match in matches:
            files_changed.add(match[0])
        
        # process each section starting with 'diff --git'
        sections = re.split(r'(?m)^diff --git', patch_text)
        for section in sections[1:]:  # Skip the first split as it's before the first 'diff --git'
            lines = section.split('\n')
            for line in lines:
                if line.startswith('+') and not line.startswith('+++'):
                    added_lines += 1
                elif line.startswith('-') and not line.startswith('---'):
                    deleted_lines += 1
        
        return len(files_changed), added_lines, deleted_lines
        
    def extract_commit_description(self, commit_hash: str) -> Optional[str]:
        """Extract the commit description.
        
        Args:
            commit_hash: Git commit hash
            
        Returns:
            Commit description or None if error occurred
        """
        try:
            result = subprocess.run(
                ['git', '-C', self.repo_path, 'log', '--format=%B', '-n', '1', commit_hash],
                stdout=subprocess.PIPE, 
                text=True, 
                encoding='utf-8'
            )
            description = result.stdout.strip()
            return description
        except subprocess.CalledProcessError as e:
            logger.error(f"Error extracting description for commit {commit_hash}")
            logger.debug(f"Error details: {e.output}")
            return None
    
    def build_code_blocks(self, files_info: Dict[str, Dict], commit_hash: str) -> Tuple[Dict[str, Dict], str, str]:
        """Build the vulnerable/patched code blocks from the extracted functions and added/deleted lines.
        
        Args:
            files_info: Dictionary with file and function information
            commit_hash: Git commit hash
            
        Returns:
            Tuple containing (updated_files_info, vulnerable_code_block, patched_code_block)
        """
        vulnerable_code_block = ""
        patched_code_block = ""

        # Process each file in the files_info
        for file_path, file_changes in files_info.items():
            file_header_printed_vulnerable = False  # Flag to track the first entry in each file for vulnerable code
            file_header_printed_patched = False     # Flag to track the first entry in each file for patched code

            # Handle function-level changes
            functions_to_modify = []
            for function_name, changes in file_changes['functions'].items():
                if not function_name:  # Skip empty string function names
                    continue
                    
                vulnerable_code = self.fetch_pre_fix_vulnerable_code(commit_hash, file_path)
                patched_code = self.fetch_fixed_code(commit_hash, file_path)

                vulnerable_function = self.extract_function(vulnerable_code, function_name)
                patched_function = self.extract_function(patched_code, function_name)

                # Check if changes are within the function
                if vulnerable_function and patched_function:
                    changes_within_vulnerable_function = self.is_change_within_function(vulnerable_function, changes)
                    changes_within_patched_function = self.is_change_within_function(patched_function, changes)

                    if changes_within_vulnerable_function or changes_within_patched_function:
                        if not file_header_printed_vulnerable:
                            vulnerable_code_block += f"// File path: {file_path}\n"
                            file_header_printed_vulnerable = True
                        if not file_header_printed_patched:
                            patched_code_block += f"// File path: {file_path}\n"
                            file_header_printed_patched = True
                        vulnerable_code_block += f"{vulnerable_function}\n"
                        patched_code_block += f"{patched_function}\n"
                    else:
                        # Process added and deleted lines
                        added_lines = '\n'.join(changes['added'])
                        deleted_lines = '\n'.join(changes['deleted'])
                        
                        # General pattern for finding a pattern for function
                        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_\* ]*\s+[a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
                        
                        # Check the function pattern in the added/deleted lines
                        added_function_signatures = re.findall(pattern, added_lines, re.MULTILINE)
                        deleted_function_signatures = re.findall(pattern, deleted_lines, re.MULTILINE)
                        
                        # Extract function name for modification
                        if added_function_signatures or deleted_function_signatures:
                            new_function_name = added_function_signatures[0] if added_function_signatures else deleted_function_signatures[0]
                            functions_to_modify.append((function_name, new_function_name))
                        else:
                            functions_to_modify.append((function_name, ""))
                else:
                    # Handle special cases for added/deleted functions
                    if 'added' in changes and changes['added']:
                        function_signatures = self.extract_function_signatures('\n'.join(changes['added']))
                        if function_signatures:
                            new_function_name = function_signatures[0]
                            functions_to_modify.append((function_name, new_function_name))
                            patched_function = self.extract_function(patched_code, new_function_name)
                        else:
                            patched_function = '\n'.join(changes['added'])
                            functions_to_modify.append((function_name, ""))
                           
                        if not file_header_printed_patched:
                            patched_code_block += f"// File path: {file_path}\n"
                            file_header_printed_patched = True
                        patched_code_block += f"{patched_function}\n"

                    if 'deleted' in changes and changes['deleted']:
                        function_signatures = self.extract_function_signatures('\n'.join(changes['deleted']))
                        if function_signatures:
                            new_function_name = function_signatures[0]
                            functions_to_modify.append((function_name, new_function_name))
                            vulnerable_function = self.extract_function(vulnerable_code, new_function_name)
                        else:
                            vulnerable_function = '\n'.join(changes['deleted'])
                            if function_name not in [f[0] for f in functions_to_modify]:
                                functions_to_modify.append((function_name, ""))

                        if not file_header_printed_vulnerable:
                            vulnerable_code_block += f"// File path: {file_path}\n"
                            file_header_printed_vulnerable = True
                        vulnerable_code_block += f"{vulnerable_function}\n"
            
            # Process function name modifications
            functions_to_modify = list(set(functions_to_modify))  # Remove duplicates
            for function_name, new_function_name in functions_to_modify:
                if not function_name:  # Skip empty string function names
                    continue
                    
                # Handle function name changes and merges
                if new_function_name in files_info[file_path]['functions']:
                    # Combine the added and deleted lines
                    combine_add = files_info[file_path]['functions'][function_name]['added'] + files_info[file_path]['functions'][new_function_name]['added']
                    combine_del = files_info[file_path]['functions'][function_name]['deleted'] + files_info[file_path]['functions'][new_function_name]['deleted']
                    # Assign the combined lines to the new function name
                    files_info[file_path]['functions'][new_function_name] = {'added': combine_add, 'deleted': combine_del}
                    # Delete the original function name
                    del files_info[file_path]['functions'][function_name]
                else:
                    # Extract the value associated with the original key
                    original_value = files_info[file_path]['functions'][function_name]
                    # Delete the original function name
                    del files_info[file_path]['functions'][function_name]
                    # Assign the extracted value to the new key
                    files_info[file_path]['functions'][new_function_name] = original_value
                
                # Skip further processing for empty function names
                if not new_function_name:
                    continue
                    
                # Skip if function has already been processed
                if (new_function_name in vulnerable_code_block) or (new_function_name in patched_code_block):
                    continue
                    
                # Extract and process the function code
                vulnerable_code = self.fetch_pre_fix_vulnerable_code(commit_hash, file_path)
                patched_code = self.fetch_fixed_code(commit_hash, file_path)
    
                vulnerable_function = self.extract_function(vulnerable_code, new_function_name)
                patched_function = self.extract_function(patched_code, new_function_name)
                
                if vulnerable_function or patched_function:
                    if not file_header_printed_vulnerable:
                        vulnerable_code_block += f"// File path: {file_path}\n"
                        file_header_printed_vulnerable = True
                    if not file_header_printed_patched:
                        patched_code_block += f"// File path: {file_path}\n"
                        file_header_printed_patched = True
                    
                    if vulnerable_function:
                        vulnerable_code_block += f"{vulnerable_function}\n"
                    if patched_function:
                        patched_code_block += f"{patched_function}\n"
            
            # Handle file-level changes
            if 'added' in file_changes and file_changes['added']:
                if not file_header_printed_patched:
                    patched_code_block += f"// File path: {file_path}\n"
                    file_header_printed_patched = True
                patched_code_block += f"{''.join(file_changes['added'])}\n"

            if 'deleted' in file_changes and file_changes['deleted']:
                if not file_header_printed_vulnerable:
                    vulnerable_code_block += f"// File path: {file_path}\n"
                    file_header_printed_vulnerable = True
                vulnerable_code_block += f"{''.join(file_changes['deleted'])}\n"

        return files_info, vulnerable_code_block, patched_code_block
        
    def num_functions_changed(self, vulnerable_code_block: str, patched_code_block: str) -> int:
        """Calculate the number of functions changed between the vulnerable and patched code blocks.
        
        Args:
            vulnerable_code_block: Vulnerable code block text
            patched_code_block: Patched code block text
            
        Returns:
            Number of unique functions changed
        """
        vulnerable_functions = self.extract_function_signatures(vulnerable_code_block)
        patched_functions = self.extract_function_signatures(patched_code_block)
        unique_functions = set(vulnerable_functions + patched_functions)
        
        return len(unique_functions) 