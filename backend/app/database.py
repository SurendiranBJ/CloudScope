import logging
from neo4j import GraphDatabase, Driver
from app.config import settings

logger = logging.getLogger("backend")

_driver: Driver | None = None

def get_driver() -> Driver:
    global _driver
    if _driver is None:
        try:
            _driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            logger.info("Initialized Neo4j connection pool wrapper")
        except Exception as e:
            logger.error(f"Failed to create Neo4j driver at {settings.NEO4J_URI}: {str(e)}")
            raise e
    return _driver

def close_driver():
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
        logger.info("Closed Neo4j connection pool")

def execute_write(query: str, parameters: dict = None) -> list:
    driver = get_driver()
    with driver.session() as session:
        result = session.run(query, parameters or {})
        return [record.data() for record in result]

def execute_read(query: str, parameters: dict = None) -> list:
    driver = get_driver()
    with driver.session() as session:
        result = session.run(query, parameters or {})
        return [record.data() for record in result]
