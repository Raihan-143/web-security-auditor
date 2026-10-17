"""
utils/logger.py
Centralized console logging utility with ANSI color support.
"""

from colorama import init, Fore, Style

# Windows terminal-e ANSI colors auto-reset support ensure
init(autoreset=True)


class ConsoleLogger:
    @staticmethod
    def success(message: str) -> None:
        """Prints a success message in green."""
        print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {message}")

    @staticmethod
    def failure(message: str) -> None:
        """Prints a failure/vulnerability message in red."""
        print(f"{Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} {message}")

    @staticmethod
    def info(message: str) -> None:
        """Prints an informational message in cyan."""
        print(f"{Fore.CYAN}{Style.BRIGHT}[*]{Style.RESET_ALL} {message}")

    @staticmethod
    def warning(message: str) -> None:
        """Prints a warning or risk mitigation detail in yellow."""
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} {message}")

    @staticmethod
    def header(title: str) -> None:
        """Prints a formatted header box."""
        border = "=" * 70
        print(f"\n{Fore.LIGHTBLACK_EX}{border}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}{title.center(70)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}{border}{Style.RESET_ALL}\n")