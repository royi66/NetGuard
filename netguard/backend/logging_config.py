import logging
import os


def clear_log_file():
    """Clear the contents of the log file if it exists."""
    log_file = 'log/netguard.log'
    if os.path.exists(log_file):
        open(log_file, 'w').close()
    print('Log file cleared.')


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
    filename='log/netguard.log',
    filemode='a'
)

logger = logging.getLogger('NetGuardLogger')

"""
logger.info("This is an info message from some_function.")
logger.warning("This is a warning message from another_function.")
logger.error("An error occurred: %s", e)
"""
