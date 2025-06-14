import os
import datetime
from colorama import init, Fore, Style
from DEFENSE.db.database import write_log

# Initialize colorama
init(autoreset=True)

# Color mapping for log levels
LOG_COLORS = {
    "severe": Fore.RED + Style.BRIGHT,
    "error": Fore.RED,
    "warning": Fore.YELLOW,
    "info": Fore.GREEN,
    "debug": Fore.CYAN,
    "default": Fore.WHITE,
}


def log_to_console(message: str, level: str = "info") -> None:
    """
    Print a colored log message to the console based on the log level.
    """
    color = LOG_COLORS.get(level.lower(), LOG_COLORS["default"])
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{color}[{timestamp}] [{level.upper()}] {message}{Style.RESET_ALL}")


def log_to_file(message: str, level: str = "info", filename: str = "app.log") -> None:
    """
    Write a log message to a file with timestamp and level.
    The log filename is automatically named according to the current day (YYYY-MM-DD.log).
    """
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    daily_filename = f"{date_str}.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level.upper()}] {message}\n"
    # Ensure directory exists
    (
        os.makedirs(os.path.dirname(daily_filename), exist_ok=True)
        if os.path.dirname(daily_filename)
        else None
    )
    with open(daily_filename, "a") as f:
        f.write(log_entry)


def log_to_db(message: str, level: str = "info") -> None:
    """
    Write a log message to the database with timestamp and level.
    """
    write_log(level, message)


def log(
    message: str,
    level: str = "info",
    to_console: bool = True,
    to_file: bool = False,
    to_db: bool = False,
    filename: str = "app.log",
) -> None:
    """
    Main logging function to log messages to console and/or file.
    """
    if to_console:
        log_to_console(message, level)
    if to_file:
        log_to_file(message, level, filename)
    if to_db:
        log_to_db(message, level)
