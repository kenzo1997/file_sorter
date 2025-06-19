class ExtractionError(Exception):
    """Custom exception for extraction-related errors."""
    def __init__(self, message, filename=None):
        super().__init__(message)
        self.filename = filename
        if filename:
            self.message = f"{message} (File: {filename})"
        else:
            self.message = message
    def __str__(self):
        return self.message
