import logging

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