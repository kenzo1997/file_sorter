import os
import json
import shutil
import re
import logging
import hashlib
import datetime # For dynamic subfolders
import subprocess # For exiftool
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Union

from ArchiveExtractor import ArchiveExtractor
from ConfigLoadError import ConfigLoadError
from FileHandler import FileHandler
from LocalMoveHandler import LocalMoveHandler

# For MP3 metadata
try:
    from mutagen.easyid3 import EasyID3
    from mutagen import MutagenError
except ImportError:
    EasyID3 = None
    MutagenError = None
    # logging.warning("mutagen library not found. MP3 metadata extraction will be disabled.")


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FileSorter:
    """
    Manages file sorting, extraction, and organization based on a JSON configuration.

    This class orchestrates the entire file sorting process. It loads a configuration,
    scans a source directory, extracts archives, matches files against rules
    (patterns, metadata), consults an LLM for unmatched files, and moves files
    to their designated locations using appropriate file handlers.
    It also supports an undo mechanism for the last performed action.

    :ivar config_path: Path to the JSON configuration file.
    :ivar config: The loaded configuration dictionary.
    :ivar downloads_path: The primary directory to scan for files.
    :ivar mappings: A list of sorting rules loaded from the config.
    :ivar default_out: The default directory for files that don't match any rule
                       or if LLM suggests default.
    :ivar base_path: The base path for LLM-suggested relative directories.
    :ivar file_handlers: A dictionary mapping destination types (e.g., "local", "nas")
                         to FileHandler instances.
    """

    def __init__(self, config_path: str):
        """
        Initializes the FileSorter with a path to the configuration file.

        :param config_path: Path to the JSON configuration file.
        :type config_path: str
        :raises ConfigLoadError: If the configuration cannot be loaded or is invalid.
        """
        self.config_path: str = config_path
        self.config: Dict[str, Any] = {}
        self.downloads_path: str = ""
        self.mappings: List[Dict[str, Any]] = []
        self.default_out: str = ""
        self.base_path: str = "" # Often same as default_out or a parent, used for LLM relative paths

        self.file_handlers: Dict[str, FileHandler] = {
            "local": LocalMoveHandler(),
            # Add other handlers like "nas", "sftp", "cloud_storage" here
        }
        self.action_log: List[Dict[str, str]] = [] # For undo functionality
        self._load_config()

    def _load_config(self) -> None:
        """
        Loads and validates the configuration from the JSON file.

        The configuration file should define `download_path`, `mappings`,
        `default_out`, and optionally `base_path`. Paths are expanded
        using `os.path.expanduser`.

        :raises ConfigLoadError: If the file is not found, JSON is invalid,
                                 or essential keys are missing or malformed.
        """
        try:
            with open(self.config_path, 'r') as file:
                data = json.load(file)

            self.downloads_path = data.get('download_path')
            self.mappings = data.get('mappings', [])
            self.default_out = data.get('default_out', './sorted_default') # Sensible default
            self.base_path = data.get('base_path', self.default_out) # LLM suggestions relative to this

            if not self.downloads_path or not self.default_out:
                raise ConfigLoadError("Core configuration keys 'download_path' or 'default_out' are missing.")

            # Expand user paths (~)
            self.downloads_path = os.path.expanduser(self.downloads_path)
            self.default_out = os.path.expanduser(self.default_out)
            self.base_path = os.path.expanduser(self.base_path)


            for i, mapping in enumerate(self.mappings):
                if 'destinations' not in mapping or not isinstance(mapping['destinations'], list):
                    raise ConfigLoadError(f"Mapping {i} missing 'destinations' list or it's not a list.")
                for dest_idx, dest_config in enumerate(mapping['destinations']):
                    if 'path' not in dest_config or 'type' not in dest_config:
                         raise ConfigLoadError(f"Destination {dest_idx} in mapping {i} missing 'path' or 'type'.")
                    #dest_config['path'] = os.path.expanduser(dest_config['path'])
                    if dest_config['type'] not in self.file_handlers:
                        logger.warning(f"Unknown destination type '{dest_config['type']}' in mapping {i}. Will be skipped.")

            logger.info("Configuration loaded successfully.")
            self.config = data # Store the full config if needed elsewhere

        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            raise ConfigLoadError(f"Configuration file not found: {self.config_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from config file {self.config_path}: {e}")
            raise ConfigLoadError(f"Invalid JSON in config: {e}")
        except ConfigLoadError as e: # Re-raise specific ConfigLoadError
             raise
        except Exception as e:
            logger.error(f"An unexpected error occurred loading config: {e}")
            raise ConfigLoadError(f"Unexpected error loading config: {e}")


    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """
        Checks if a filename matches a wildcard pattern (e.g., "*.txt", "file?.log").

        The matching is case-insensitive. Wildcards `*` and `?` are supported.

        :param filename: The name of the file to check.
        :type filename: str
        :param pattern: The wildcard pattern.
        :type pattern: str
        :return: True if the filename matches the pattern, False otherwise.
        :rtype: bool
        """
        regex = '^' + re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.') + '$'
        return re.fullmatch(regex, filename, re.IGNORECASE) is not None


    def _matches_regex(self, filename: str, regex: str) -> bool:
        """
        Checks if a filename fully matches a regular expression.

        :param filename: The name of the file to check.
        :type filename: str
        :param regex: The regular expression string.
        :type regex: str
        :return: True if the filename matches the regex, False otherwise or if regex is invalid.
        :rtype: bool
        """
        try:
            return re.fullmatch(regex, filename) is not None
        except re.error as e:
            logger.error(f"Invalid regex '{regex}': {e}")
            return False

    def _calculate_hash(self, file_path: str, hash_algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculates the cryptographic hash of a file.

        Useful for detecting duplicate files or verifying integrity, though
        not directly used for duplicate resolution in the current move logic.

        :param file_path: The path to the file.
        :type file_path: str
        :param hash_algorithm: The hashing algorithm to use (e.g., 'sha256', 'md5').
                               Defaults to 'sha256'.
        :type hash_algorithm: str
        :return: The hexadecimal string of the hash, or None if an error occurs.
        :rtype: Optional[str]
        """
        try:
            hasher = hashlib.new(hash_algorithm)
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error for {file_path}: {e}")
            return None

    def _extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extracts metadata from various file types.

        Currently supports:
        - Images (jpg, jpeg, png, gif, tiff, heic) using `exiftool` (must be in PATH).
        - MP3 audio files using `mutagen.easyid3` (if mutagen is installed).

        :param file_path: The path to the file from which to extract metadata.
        :type file_path: str
        :return: A dictionary containing extracted metadata key-value pairs.
                 Returns an empty dictionary if no metadata is found or an error occurs.
        :rtype: Dict[str, Any]
        """
        metadata: Dict[str, Any] = {}
        file_ext = os.path.splitext(file_path)[1].lower()

        if file_ext in (".jpg", ".jpeg", ".png", ".gif", ".tiff", ".heic"): # Common image types
            try:
                # Ensure exiftool is installed and in PATH
                result = subprocess.run(['exiftool', '-j', '-G', file_path], capture_output=True, text=True, check=True)
                # exiftool returns a list of dictionaries, even for one file
                metadata_list = json.loads(result.stdout)
                if metadata_list:
                    metadata = metadata_list[0] # Take the first item
            except FileNotFoundError:
                logger.warning("exiftool not found. Image metadata extraction will be limited/disabled.")
            except subprocess.CalledProcessError as e:
                logger.warning(f"exiftool error for {file_path}: {e.stderr or e.stdout or e}")
            except json.JSONDecodeError as e:
                logger.warning(f"Error decoding exiftool JSON for {file_path}: {e}")
            except Exception as e:
                logger.warning(f"Error extracting image metadata for {file_path}: {e}")

        elif file_ext == ".mp3" and EasyID3: # Check if EasyID3 was imported
            try:
                audio = EasyID3(file_path)
                for k, v_list in audio.items(): # EasyID3 values are lists
                    # Take the first element if list is not empty, otherwise store as is (or None)
                    metadata[k] = v_list[0] if isinstance(v_list, list) and v_list else v_list
            except MutagenError as e: # Specific error from mutagen
                logger.warning(f"Error extracting MP3 metadata for {file_path} using mutagen: {e}")
            except Exception as e: # Other potential errors
                logger.warning(f"Unexpected error extracting MP3 metadata for {file_path}: {e}")
        # Add more metadata extractors (e.g., for PDFs, documents)
        return metadata

    def _compare_metadata(self, metadata: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
        """
        Compares extracted file metadata against a set of defined criteria.

        Criteria are defined in the configuration and can use operators like
        `$eq` (equals), `$ne` (not equals), `$gt` (greater than), `$lt` (less than),
        `$gte` (greater than or equals), `$lte` (less than or equals),
        `$regex` (matches regex), `$in` (value is in list), `$nin` (value is not in list).

        For numeric comparisons, values are attempted to be cast to float.
        Metadata keys can be specified directly (e.g., "ImageWidth") and the method
        will attempt to match them even if `exiftool` prefixes them with a group
        (e.g., "EXIF:ImageWidth").

        :param metadata: The dictionary of metadata extracted from the file.
        :type metadata: Dict[str, Any]
        :param criteria: A dictionary defining the metadata conditions to check.
                         Example: `{"ImageWidth": {"$gt": 1024}, "Artist": {"$eq": "MyArtist"}}`
        :type criteria: Dict[str, Any]
        :return: True if all criteria are met, False otherwise.
        :rtype: bool
        """
        if not metadata: # No metadata extracted, so criteria can't match unless criteria is empty
            return not criteria # True if criteria is also empty, False otherwise

        for key, condition_dict in criteria.items():
            if not isinstance(condition_dict, dict):
                logger.warning(f"Invalid metadata condition for key '{key}'. Expected a dictionary of operators.")
                return False # Invalid criteria structure

            actual_value = None
            # Simple key match or suffix match (e.g. user provides "ImageWidth", exiftool has "EXIF:ImageWidth")
            if key in metadata:
                actual_value = metadata[key]
            else:
                for meta_key_from_file in metadata.keys(): # Iterate through keys extracted from file
                    if meta_key_from_file.endswith(f":{key}"): # Handles group prefixes like EXIF:ImageWidth
                        actual_value = metadata[meta_key_from_file]
                        break
            
            if actual_value is None: # Key specified in criteria not found in extracted metadata
                return False

            # Ensure actual_value is comparable if condition involves numeric comparison
            # Try to convert to a number if operator suggests numeric comparison
            is_numeric_op = any(op in condition_dict for op in ["$gt", "$lt", "$gte", "$lte"])
            temp_actual_value = actual_value # Use a temp value for potential conversion
            if is_numeric_op:
                try:
                    temp_actual_value = float(temp_actual_value)
                except (ValueError, TypeError):
                    logger.warning(f"Metadata value '{temp_actual_value}' for key '{key}' is not numeric for comparison. Criterion fails.")
                    return False

            for op, target_value_from_config in condition_dict.items():
                current_target_value = target_value_from_config
                if is_numeric_op: # Ensure target is also numeric for these ops
                    try:
                        current_target_value = float(current_target_value)
                    except (ValueError, TypeError):
                         logger.warning(f"Target value '{current_target_value}' for operator '{op}' on key '{key}' is not numeric. Criterion fails.")
                         return False

                # Perform comparison
                match = False
                if op == "$eq": match = (temp_actual_value == current_target_value)
                elif op == "$ne": match = (temp_actual_value != current_target_value)
                elif op == "$gt" and is_numeric_op: match = (temp_actual_value > current_target_value)
                elif op == "$lt" and is_numeric_op: match = (temp_actual_value < current_target_value)
                elif op == "$gte" and is_numeric_op: match = (temp_actual_value >= current_target_value)
                elif op == "$lte" and is_numeric_op: match = (temp_actual_value <= current_target_value)
                elif op == "$regex":
                    match = (isinstance(temp_actual_value, str) and
                             bool(re.search(str(current_target_value), temp_actual_value)))
                elif op == "$in" and isinstance(current_target_value, list): match = (temp_actual_value in current_target_value)
                elif op == "$nin" and isinstance(current_target_value, list): match = (temp_actual_value not in current_target_value)
                else:
                    logger.warning(f"Unsupported metadata operator '{op}' or type mismatch for key '{key}'. Criterion fails.")
                    return False
                
                if not match:
                    return False # If any condition for this key fails, the whole key criterion fails
        return True # All criteria passed

    def _sanitize_path_component(self, path_component: str) -> str:
        """
        Sanitizes a single path component (directory or filename part) to remove invalid characters.

        Removes characters like `<`, `>`, `:`, `"`, `/`, `\`, `|`, `?`, `*`.
        Also strips leading/trailing whitespace, dots, and colons (unless part of a drive letter).

        :param path_component: The path component string to sanitize.
        :type path_component: str
        :return: The sanitized path component.
        :rtype: str
        """
        # Remove characters invalid in Windows/Linux filenames/paths.
        # Slashes/backslashes are handled by splitting/joining, so they are removed here from individual components.
        sanitized = re.sub(r'[<>:"/\\|?*]', '', path_component)
        # On Windows, also remove colons if not part of a drive letter at the start.
        if os.name == 'nt':
            if ':' in sanitized and not re.match(r'^[a-zA-Z]:', sanitized):
                 sanitized = sanitized.replace(':', '')
        return sanitized.strip().strip('. ') # Also strip leading/trailing dots and spaces

    def _move_file_to_destinations(self, file_path: str, destination_configs: List[Dict[str, Any]], original_filename_for_subfolder: str) -> bool:
        """
        Moves/handles a file to one or more destinations based on their type and configuration.

        Iterates through the `destination_configs` list. For each configuration, it determines
        the final destination path (including dynamic subfolders) and uses the appropriate
        `FileHandler` to perform the operation.
        Logs the action for potential undo.

        If multiple destinations are configured for a "move" operation, the file is typically
        consumed by the first successful handler. Subsequent "move" handlers for the same
        original file would likely fail unless they are designed as "copy" operations or
        the file_path is updated to the new location (not current behavior for simplicity).

        :param file_path: The current path of the file to be moved/handled.
        :type file_path: str
        :param destination_configs: A list of destination configuration dictionaries.
                                    Each dict should specify 'type', 'path', and optionally
                                    'subfolders' and 'credentials'.
        :type destination_configs: List[Dict[str, Any]]
        :param original_filename_for_subfolder: The original name of the item being processed,
                                                used for consistent subfolder naming, especially
                                                if `file_path` points to a temporarily extracted file.
        :type original_filename_for_subfolder: str
        :return: True if at least one destination handling was successful, False otherwise.
        :rtype: bool
        """
        at_least_one_success = False
        original_source_path_for_log = file_path # Path when this method is called

        for dest_config in destination_configs:
            dest_type = dest_config.get('type', 'local') # Default to local if not specified
            print(dest_config.get('path'))
            base_dest_path = dest_config.get('path')
            subfolder_pattern = dest_config.get("subfolders", "")
            credentials = dest_config.get('credentials')

            if not base_dest_path:
                logger.warning(f"Destination config missing 'path'. Skipping for {file_path}")
                continue

            handler = self.file_handlers.get(dest_type)
            if not handler:
                logger.warning(f"No handler for destination type '{dest_type}'. Skipping destination {base_dest_path} for {file_path}")
                continue

            # Apply subfolder pattern
            final_dest_dir = base_dest_path
            if subfolder_pattern:
                now = datetime.datetime.now()
                file_ext_for_subfolder = os.path.splitext(original_filename_for_subfolder)[1]
                if file_ext_for_subfolder.startswith('.'):
                    file_ext_for_subfolder = file_ext_for_subfolder[1:]

                # Prepare format_map, being careful with missing keys if pattern is complex
                format_map = {
                    "YYYY": str(now.year),
                    "MM": f"{now.month:02d}",
                    "DD": f"{now.day:02d}",
                    "file_type": file_ext_for_subfolder.lower() or "unknown",
                    "filename": os.path.splitext(original_filename_for_subfolder)[0]
                }
                try:
                    temp_subfolder_path = subfolder_pattern
                    for key, value in format_map.items():
                        temp_subfolder_path = temp_subfolder_path.replace(f"{{{key}}}", value)
                    # Remove any unformatted placeholders like {unknown_placeholder}
                    subfolder_path_resolved = re.sub(r'\{[^}]+\}', '', temp_subfolder_path)

                except KeyError as e: # Should not happen if format_map is complete for pattern
                    logger.warning(f"Subfolder pattern '{subfolder_pattern}' contains unknown placeholder: {e}. Using base destination path.")
                    subfolder_path_resolved = "" # Fallback or handle differently

                # Sanitize each component of the subfolder path
                if subfolder_path_resolved:
                    subfolder_components = re.split(r'[/\\]', subfolder_path_resolved)
                    sanitized_subfolder_components = [self._sanitize_path_component(comp) for comp in subfolder_components if comp.strip()]
                    if sanitized_subfolder_components:
                        final_dest_dir = os.path.join(base_dest_path, *sanitized_subfolder_components)

            destination_full_path = os.path.join(final_dest_dir, os.path.basename(original_filename_for_subfolder))

            if handler.handle(file_path, destination_full_path, credentials):
                self.action_log.append({
                    "action": "move",
                    "source_original": original_source_path_for_log,
                    "source_current": destination_full_path, # Where it ended up
                    "destination_original_config_path": base_dest_path # Log the original target dir from config
                })
                at_least_one_success = True
                break # Exit after first successful handling for this file_path
            else:
                logger.error(f"Failed to handle {file_path} for destination {final_dest_dir}")
        
        return at_least_one_success

    def process_files(self, current_path: Optional[str] = None, is_recursive_call: bool = False):
        current_path = current_path or self.downloads_path

        if not os.path.exists(current_path):
            logger.error(f"Download path does not exist: {current_path}")
            return

        logger.info(f"Processing directory: {current_path}")
        
        # Stage 1: Extract archives and restart if any extracted
        if self._extract_archives(current_path):
            logger.info("Archives extracted. Restarting processing to include new contents.")
            self.process_files(current_path, is_recursive_call)
            return
        
        # Stage 2: Process files and folders
        processed_items = self._handle_files_and_dirs(current_path)

        
        # Stage 3: Recurse into unprocessed directories
        self._recurse_unprocessed_dirs(current_path, processed_items)

        # Stage 4: Clean up empty folder if this is a recursive call
        if is_recursive_call:
            self._cleanup_if_empty(current_path)


    def _extract_archives(self, path: str) -> bool:
        extracted = False
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isfile(full_path):
                if ArchiveExtractor.extract(full_path, path):
                    logger.info(f"Extracted archive: {full_path}")
                    extracted = True
        return extracted
    
    def _handle_files_and_dirs(self, path: str) -> set:
        processed = set()
        for item in os.listdir(path):
            full_path = os.path.join(path, item)

            if os.path.isdir(full_path):
                if self._is_excluded_folder(item):
                    logger.info(f"Skipping excluded folder: {full_path}")
                    processed.add(item)
                    continue

                # Try to match directory against mappings
                if self._process_file(full_path, item, is_dir=True):
                    processed.add(item)

            elif os.path.isfile(full_path):
                logger.info(f"Processing file: {full_path}")
                if self._process_file(full_path, item):
                    processed.add(item)

        return processed

    def _process_file(self, full_path: str, filename: str, is_dir: bool = False) -> bool:
        ext = os.path.splitext(filename)[1][1:].lower() if not is_dir else ""
        matched = False

        for mapping in self.mappings:
            for pattern in mapping.get('include', []):
                if self._matches_pattern_type(filename, ext, pattern):
                    # Skip metadata check for directories unless needed
                    logger.info(f"{'Directory' if is_dir else 'File'} {filename} matched pattern '{pattern}'.")

                    moved = self._move_file_to_destinations(
                        full_path, mapping.get('destinations', []), filename
                    )
                    
                    matched = True
                    if moved and not os.path.exists(full_path):
                        return True
        return matched



    def _matches_pattern_type(self, filename: str, ext: str, pattern: str) -> bool:
        if pattern.startswith("/") and pattern.endswith("/"):
            return self._matches_regex(filename, pattern[1:-1])
        elif "*" in pattern or "?" in pattern:
            return self._matches_pattern(filename, pattern)
        else:
            return filename.lower().endswith(f".{pattern.lower()}") if ext == pattern.lower() else False

    def _is_excluded_folder(self, folder_name: str) -> bool:
        for mapping in self.mappings:
            if folder_name.lower() in [f.lower() for f in mapping.get("exclude_folders", [])]:
                return True
        return False

    def _recurse_unprocessed_dirs(self, path: str, processed_items: set):
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if item in processed_items or not os.path.isdir(full_path):
                continue

            if self._is_excluded_folder(item):
                logger.info(f"Skipping excluded folder (recursive check): {full_path}")
                continue

            logger.info(f"Recursively processing directory: {full_path}")
            self.process_files(full_path, is_recursive_call=True)


    def _cleanup_if_empty(self, path: str):
        if os.path.exists(path) and not os.listdir(path):
            try:
                os.rmdir(path)
                logger.info(f"Deleted empty folder: {path}")
            except OSError as e:
                logger.error(f"Error deleting folder {path}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error deleting folder {path}: {e}")
