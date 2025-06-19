class ConfigLoadError(Exception):
    """
    Exception raised when configuration loading fails.

    This can be due to a missing file, invalid JSON, or missing
    required configuration keys.
    """
    pass

