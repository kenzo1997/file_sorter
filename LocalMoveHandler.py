from FileHandler import FileHandler
from typing import Dict, Optional
import shutil
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class LocalMoveHandler(FileHandler):
    """
    Handles moving files locally on the filesystem.

    Implements the `handle` method to perform a `shutil.move` operation.
    Uses interactive duplicate handling from the base class.
    """
    def handle(self, source_path: str, destination_full_path: str, credentials: Optional[Dict[str, str]] = None) -> bool:
        """
        Moves a file from `source_path` to `destination_full_path` on the local filesystem.

        If a file already exists at `destination_full_path`, it uses `_handle_duplicates_interactive`.
        The destination directory is created if it doesn't exist.

        :param source_path: The path of the file to move.
        :type source_path: str
        :param destination_full_path: The full target path (including filename) for the file.
        :type destination_full_path: str
        :param credentials: Not used for local moves.
        :type credentials: Optional[Dict[str, str]]
        :return: True if the move was successful, False otherwise.
        :rtype: bool
        """
        try:
            resolved_dest_path = self._handle_duplicates_interactive(source_path, destination_full_path)
            if resolved_dest_path is None: # Skipped or cancelled
                return False

            self._ensure_destination_dir_exists(resolved_dest_path)
            shutil.move(source_path, resolved_dest_path)
            logger.info(f"Moved {source_path} to {resolved_dest_path}")
            return True
        except Exception as e:
            logger.error(f"Error moving {source_path} to {destination_full_path}: {e}")
            return False


