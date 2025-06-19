import logging
from FileSorter import FileSorter

# Setup global logging configuration once
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """
    Main function that initializes the FileSorter class, loads configuration,
    and processes files based on the provided rules in the configuration file.

    The configuration is loaded from 'rule.json' and processed through the
    FileSorter class, which manages file sorting and handling based on the
    rules defined in the config.
    """

    sorter = FileSorter("rule.json")
    sorter.process_files()

main()
