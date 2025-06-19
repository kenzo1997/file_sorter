from abc import ABC, abstractmethod
from typing import Dict, Optional
import os
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FileHandler(ABC):
    """
    Abstract base class for handling files (e.g., move, copy).

    Subclasses must implement the `handle` method to perform the specific
    file operation. It also provides helper methods for common tasks like
    ensuring destination directory existence and interactive duplicate handling.
    """
    @abstractmethod
    def handle(self, source_path: str, destination_full_path: str, credentials: Optional[Dict[str, str]] = None) -> bool:
        """
        Handles the file operation (e.g., move, copy).

        This method must be implemented by subclasses.

        :param source_path: The path of the file to handle.
        :type source_path: str
        :param destination_full_path: The full path (including filename) for the destination.
        :type destination_full_path: str
        :param credentials: Optional credentials for remote operations.
        :type credentials: Optional[Dict[str, str]]
        :return: True if successful, False otherwise.
        :rtype: bool
        """
        raise NotImplementedError
        #pass

    def _ensure_destination_dir_exists(self, destination_full_path: str):
        """
        Helper to create destination directory if it doesn't exist.

        :param destination_full_path: The full path to the destination file.
                                      The directory part of this path will be created.
        :type destination_full_path: str
        """
        dest_dir = os.path.dirname(destination_full_path)
        if not os.path.exists(dest_dir):
           os.makedirs(dest_dir, exist_ok=True)
           logger.info(f"Created directory: {dest_dir}")

    def _handle_duplicates_interactive(self, source_path: str, destination_full_path: str) -> Optional[str]:
        """
        Handles duplicate files interactively when a file already exists at the destination.

        Prompts the user to choose an action: rename the new file, replace the existing one,
        skip this file, or cancel the operation for this file.

        :param source_path: The path of the source file being processed.
        :type source_path: str
        :param destination_full_path: The intended full path for the destination file.
        :type destination_full_path: str
        :return: The new resolved destination_full_path if an action is taken (e.g., after renaming),
                 the original `destination_full_path` if no duplicate or if "replace" is chosen,
                 or None if the file operation should be skipped or was cancelled.
        :rtype: Optional[str]
        """
        base, ext = os.path.splitext(os.path.basename(destination_full_path))
        dest_dir = os.path.dirname(destination_full_path)
        # counter = 1 # Not used here, rename logic is different

        original_destination_full_path = destination_full_path

        # This loop only runs if the destination_full_path *initially* exists.
        # Subsequent checks for renamed files are handled differently.
        if os.path.exists(destination_full_path): # Check only once if the initial proposed path exists
            logger.warning(f"Duplicate file found: {destination_full_path} (original source: {source_path})")
            while True: # Loop for user input until a valid action resolves the situation
                action = input(f"File '{os.path.basename(destination_full_path)}' already exists in '{dest_dir}'. "
                               "Choose action (rename_new/replace/skip/cancel): ").lower()
                if action == "rename_new":
                    # Find a new name for the incoming file by appending _N to the source filename
                    temp_counter = 1
                    new_name_base = os.path.splitext(os.path.basename(source_path))[0]
                    new_ext = os.path.splitext(os.path.basename(source_path))[1]
                    while True:
                        renamed_file_name = f"{new_name_base}_{temp_counter}{new_ext}"
                        new_dest_path_for_rename = os.path.join(dest_dir, renamed_file_name)
                        if not os.path.exists(new_dest_path_for_rename):
                            destination_full_path = new_dest_path_for_rename
                            logger.info(f"New file will be renamed to: {os.path.basename(destination_full_path)}")
                            return destination_full_path # Return the new path for the source file
                        temp_counter += 1
                elif action == "replace":
                    try:
                        os.remove(original_destination_full_path) # remove the one at the original dest path
                        logger.info(f"Replaced existing file: {original_destination_full_path}")
                        return original_destination_full_path # Move to the original path
                    except Exception as e:
                        logger.error(f"Error replacing file {original_destination_full_path}: {e}")
                        return None # Error
                elif action == "skip":
                    logger.info(f"Skipping file: {source_path}")
                    return None
                elif action == "cancel":
                    logger.info(f"Cancelling move of {source_path}")
                    return None # Indicate cancellation
                else:
                    logger.warning("Invalid action. Please choose rename_new, replace, skip, or cancel.")
        return destination_full_path # No duplicate initially found, or it was resolved.

