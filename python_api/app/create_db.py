import logging

# Import engine and Base from the database module
from .database import engine, Base

# Import all models from the models module
# This is crucial so that Base.metadata knows about them
from .models import Device, NetworkInterfaceMetric

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_db():
    logger.info("Attempting to create database tables...")
    try:
        # The models are already registered with Base.metadata by importing them
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables creation process completed.")
        logger.info(f"Tables expected: {Base.metadata.tables.keys()}")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise


if __name__ == "__main__":
    init_db()