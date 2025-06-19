import zipfile
import tarfile
import gzip
import shutil # For shutil.copyfileobj in ungzip
import os
import logging

# Attempt to import optional libraries and set flags
try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False
    #logging.warning("py7zr library not found. 7z extraction will not be available.")

try:
    import rarfile
    # You might need to install unrar command-line tool as well for rarfile to work
    # sudo apt-get install unrar or brew install unrar
    # rarfile.UNRAR_TOOL = "unrar" # Optional: specify path to unrar executable
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False
    #logging.warning("rarfile library not found. RAR extraction will not be available.")

try:
    import magic # python-magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    #logging.warning("python-magic library not found. File type detection will rely on extensions only.")

# Setup logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)

class ArchiveExtractor:
    """
    Handles the extraction of various archive formats (.zip, .tar, .gz, .7z, .rar)
    with support for recursive extraction.
    """

    @staticmethod
    def get_file_type(file_path: str) -> str | None:
        """
        Detects the actual file type using python-magic (content type) if available,
        otherwise falls back to file extension.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found for type detection: {file_path}")
            return None

        if HAS_MAGIC:
            try:
                mime_type = magic.from_file(file_path, mime=True)
                return mime_type
            except magic.MagicException as e:
                logging.warning(f"python-magic could not determine file type for {file_path}: {e}. Falling back to extension.")
            except Exception as e: # Catch any other unexpected errors from magic
                logging.error(f"Unexpected error using python-magic for {file_path}: {e}. Falling back to extension.")

        # Fallback to extension if magic is not available or failed
        _, extension = os.path.splitext(file_path.lower())
        if extension == ".zip":
            return "application/zip"
        if extension in [".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"]:
            return "application/x-tar"
        if extension == ".gz":
            return "application/gzip"
        if extension == ".7z":
            return "application/x-7z-compressed"
        if extension == ".rar":
            return "application/vnd.rar" # Common MIME for .rar
        
        logging.warning(f"Could not determine specific MIME type for {file_path} using extension '{extension}'.")
        return None # Or return a generic 'application/octet-stream' if preferred

    @staticmethod
    def _unzip(file_path: str, target_dir: str):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)
            logging.info(f"Successfully extracted ZIP: {file_path} to {target_dir}")
        except zipfile.BadZipFile as e:
            raise ExtractionError(f"Bad ZIP file format", file_path) from e
        except Exception as e:
            raise ExtractionError(f"Failed to extract ZIP", file_path) from e

    @staticmethod
    def _untar(file_path: str, target_dir: str):
        try:
            # 'r:*' lets tarfile auto-detect the compression (e.g., gz, bz2)
            with tarfile.open(file_path, 'r:*') as tar_ref:
                tar_ref.extractall(target_dir)
            logging.info(f"Successfully extracted TAR: {file_path} to {target_dir}")
        except tarfile.TarError as e:
            raise ExtractionError(f"Bad TAR file format or error", file_path) from e
        except Exception as e:
            raise ExtractionError(f"Failed to extract TAR", file_path) from e

    @staticmethod
    def _ungzip(file_path: str, target_dir: str) -> str:
        """
        Extracts a GZIP archive.
        Returns the path of the extracted file.
        """
        base_name = os.path.basename(file_path)
        output_filename = os.path.splitext(base_name)[0] # Remove .gz
        output_file_path = os.path.join(target_dir, output_filename)

        try:
            os.makedirs(target_dir, exist_ok=True) # Ensure target directory exists
            with gzip.open(file_path, 'rb') as f_in:
                with open(output_file_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            logging.info(f"Successfully extracted GZIP: {file_path} to {output_file_path}")
            return output_file_path
        except FileNotFoundError: # Should be caught by initial check in extract usually
            raise ExtractionError(f"GZIP source file not found", file_path) from None
        except Exception as e:
            raise ExtractionError(f"Failed to extract GZIP", file_path) from e

    @staticmethod
    def _un7z(file_path: str, target_dir: str):
        if not HAS_PY7ZR:
            raise ExtractionError("py7zr library is not installed. Cannot extract 7z files.", file_path)
        try:
            with py7zr.SevenZipFile(file_path, mode='r') as z_ref:
                z_ref.extractall(path=target_dir)
            logging.info(f"Successfully extracted 7Z: {file_path} to {target_dir}")
        except py7zr.exceptions.Bad7zFile as e:
            raise ExtractionError(f"Bad 7Z file format", file_path) from e
        except Exception as e:
            raise ExtractionError(f"Failed to extract 7Z", file_path) from e

    @staticmethod
    def _unrar(file_path: str, target_dir: str):
        if not HAS_RARFILE:
            raise ExtractionError("rarfile library is not installed. Cannot extract RAR files.", file_path)
        try:
            # Ensure unrar command is available if rarfile needs it
            if rarfile.NEED_COMMENTS_FIX and not rarfile.custom_tool_path_set:
                 pass # rarfile will try to find it or use internal
            with rarfile.RarFile(file_path, 'r') as r_ref:
                r_ref.extractall(path=target_dir)
            logging.info(f"Successfully extracted RAR: {file_path} to {target_dir}")
        except rarfile.RarCannotExec as e:
            # This often means the 'unrar' command-line tool is not found or not executable
            logging.error("The 'unrar' command-line tool might be missing or not executable.")
            raise ExtractionError(f"RAR extraction failed (unrar tool issue?)", file_path) from e
        except rarfile.BadRarFile as e: # More specific than just rarfile.Error
            raise ExtractionError(f"Bad RAR file format", file_path) from e
        except rarfile.Error as e: # General rarfile errors
            raise ExtractionError(f"Failed to extract RAR", file_path) from e
        except Exception as e:
            raise ExtractionError(f"An unexpected error occurred during RAR extraction", file_path) from e


    @staticmethod
    def extract(file_path: str, target_dir: str, depth: int = 0, max_depth: int = 5, delete_original: bool = True):
        """
        Handles the extraction process based on file type and allows recursive extraction.

        Args:
            file_path (str): The path to the archive file.
            target_dir (str): The directory where contents should be extracted.
            depth (int): Current recursion depth.
            max_depth (int): Maximum recursion depth to prevent infinite loops.
            delete_original (bool): If True, deletes the original archive file after successful extraction.
        """
        if not os.path.isfile(file_path):
            logging.error(f"Archive file not found: {file_path}")
            return

        if depth >= max_depth:
            logging.warning(f"Max extraction depth ({max_depth}) reached for {file_path}. Skipping further recursion here.")
            return

        logging.info(f"Processing (Depth {depth}): {file_path}")
        os.makedirs(target_dir, exist_ok=True) # Ensure target directory exists

        file_type_mime = ArchiveExtractor.get_file_type(file_path)
        # If get_file_type returned None (e.g. file deleted between check and processing), log and exit for this file.
        if file_type_mime is None and not os.path.exists(file_path): # Re-check existence if mime is None
             logging.error(f"File {file_path} disappeared before extraction could start.")
             return
        if file_type_mime is None: # If still None, but file exists, it's genuinely unknown/unsupported by extension
            logging.warning(f"Could not determine archive type for {file_path} via MIME or extension. Cannot extract.")
            return

        extracted_successfully = False
        # Store paths of items created by extraction for potential recursion
        # For archives like zip/tar, we'll scan target_dir. For gzip, it's a single file.
        extracted_item_paths_for_recursion = []

        try:
            if file_type_mime == 'application/zip':
                ArchiveExtractor._unzip(file_path, target_dir)
                extracted_successfully = True
            elif file_type_mime == 'application/x-tar':
                ArchiveExtractor._untar(file_path, target_dir)
                extracted_successfully = True
            elif file_type_mime == 'application/gzip':
                # _ungzip returns the path of the single extracted file
                extracted_file = ArchiveExtractor._ungzip(file_path, target_dir)
                extracted_item_paths_for_recursion.append(extracted_file)
                extracted_successfully = True
            elif file_type_mime == 'application/x-7z-compressed':
                if HAS_PY7ZR:
                    ArchiveExtractor._un7z(file_path, target_dir)
                    extracted_successfully = True
                else:
                    logging.warning(f"Skipping 7Z file {file_path}: py7zr library not available.")
            elif file_type_mime == 'application/vnd.rar' or file_type_mime == 'application/x-rar-compressed': # x-rar-compressed is also common
                if HAS_RARFILE:
                    ArchiveExtractor._unrar(file_path, target_dir)
                    extracted_successfully = True
                else:
                    logging.warning(f"Skipping RAR file {file_path}: rarfile library not available.")
            else:
                logging.warning(f"Unsupported archive type '{file_type_mime}' for {file_path}")
                return # Not an error, just unsupported

            if extracted_successfully:
                logging.info(f"Extraction of {file_path} to {target_dir} completed.")
                if delete_original:
                    try:
                        os.remove(file_path)
                        logging.info(f"Original file {file_path} deleted.")
                    except OSError as e:
                        logging.error(f"Failed to delete original file {file_path}: {e}")

                # --- Recursive Extraction ---
                # If extraction created a single file (like .gz), recurse on that.
                # Otherwise, scan the target_dir for new archives.
                if not extracted_item_paths_for_recursion: # i.e., it was a multi-file archive like zip/tar
                    # To avoid re-processing already processed items if target_dir is reused across levels,
                    # it's safer to get a list of items *before* extraction if possible, or be very specific.
                    # For simplicity here, we list all items in target_dir.
                    # A more robust approach might involve extracting to a temporary unique sub-directory
                    # and then moving contents, or tracking exact files created by the archive.
                    for item_name in os.listdir(target_dir):
                        item_path = os.path.join(target_dir, item_name)
                        if os.path.isfile(item_path): # Only consider files for further extraction
                             extracted_item_paths_for_recursion.append(item_path)
                
                logging.info(f"Checking {len(extracted_item_paths_for_recursion)} extracted items for further archives...")
                for item_path in extracted_item_paths_for_recursion:
                    if os.path.isfile(item_path): # Ensure it's a file
                        # Check if the newly extracted item is itself an archive
                        item_type_mime = ArchiveExtractor.get_file_type(item_path)
                        if item_type_mime and item_type_mime in [
                            'application/zip', 'application/x-tar', 'application/gzip',
                            'application/x-7z-compressed', 'application/vnd.rar', 'application/x-rar-compressed'
                        ]:
                            logging.info(f"Found nested archive: {item_path} (Type: {item_type_mime}). Attempting recursive extraction.")
                            # For nested archives, decide on target:
                            # Option 1: Extract into the same target_dir
                            # Option 2: Create a subdirectory named after the archive
                            # Using Option 1 for simplicity here.
                            ArchiveExtractor.extract(item_path, target_dir, depth + 1, max_depth, delete_original)
                        # else:
                            # logging.debug(f"Item {item_path} is not a recognized archive type for recursion (MIME: {item_type_mime}).")

        except ExtractionError as e:
            logging.error(f"Extraction failed for {file_path}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing {file_path}: {e}", exc_info=True)
