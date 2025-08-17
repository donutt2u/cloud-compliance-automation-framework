"""Structured logging configuration."""

import sys
from pathlib import Path
from loguru import logger


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured logging."""

    # Remove default handler
    logger.remove()

    # Add console handler
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>",
        level=log_level,
        colorize=True,
        serialize=False,
    )

    # Ensure logs directory exists
    Path("logs").mkdir(exist_ok=True)

    # Add file handler
    logger.add(
        "logs/compliance-framework.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=log_level,
        rotation="10 MB",
        retention="30 days",
        compression="gz",
    )


def get_logger(name: str):
    """Get a configured logger instance."""
    return logger.bind(name=name)
