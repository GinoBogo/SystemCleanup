#!/usr/bin/env python3

"""
Robust System Cleanup Script for Arch Linux and Ubuntu

Improved error handling, input validation, dry-run mode, safe logging setup with
colorized log output including cyan step headers, permission checks, concurrency
and file operation safety, configurability, and modular well-typed code.

Author: Gino Bogo
License: MIT
Version: 1.1
"""

import getpass
import json
import logging
import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Dict, List, Optional, Set, Tuple, cast

# ==============================================================================
# GLOBAL CONSTANTS AND SETUP
# ==============================================================================

logger = logging.getLogger("system_cleanup")
logger.setLevel(logging.INFO)

# Define custom STEP level
STEP = 25
logging.addLevelName(STEP, "STEP")

gui_input_handler = None  # Global input handler for GUI mode


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================


def log_step(message: str) -> None:
    """Logs a message formatted as a processing step."""
    logger.log(STEP, f"--- {message} ---")


def safe_input(
    prompt: str, valid_responses: List[str], default: Optional[str] = None
) -> str:
    """Delegates input request to GUI handler or returns default."""
    if gui_input_handler:
        result = gui_input_handler.request(prompt, valid_responses, default)
        if result is not None:
            return result
    if default is not None:
        return default
    return ""


def check_command_exists(command: str) -> bool:
    """Checks if a command exists on the system."""
    return shutil.which(command) is not None


def format_size_bytes(size_bytes: int) -> str:
    """Formats a byte count into a human-readable string."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def sanitize_path(path_str: str) -> str:
    """Sanitizes a path string to prevent shell injection."""
    # Remove newlines, semicolons, and other shell metacharacters
    return (
        path_str.replace("\n", "").replace(";", "").replace("`", "").replace("$(", "")
    )


# ==============================================================================
# CORE CLASSES
# ==============================================================================


class CommandExecutor:
    """Handles shell command execution with dry-run support and error handling."""

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run
        self._sudo_password: Optional[bytes] = (
            None  # Store as bytes for better security
        )
        self._password_attempts = 0
        self._max_password_attempts = 3

    def _clear_password(self) -> None:
        """Securely clears the password from memory."""
        if self._sudo_password:
            # Overwrite the bytes with zeros before clearing
            import ctypes

            ctypes.memset(
                ctypes.c_char_p(self._sudo_password), 0, len(self._sudo_password)
            )
            self._sudo_password = None

    def _get_sudo_password(self) -> Optional[bytes]:
        """Gets sudo password from GUI or console with security measures."""
        if self._sudo_password is not None:
            return self._sudo_password

        if self._password_attempts >= self._max_password_attempts:
            logger.error("Too many failed password attempts")
            return None

        if gui_input_handler:
            password = gui_input_handler.request_password(
                "Authentication Required", "Enter password for system cleanup:"
            )
            if password:
                self._sudo_password = password.encode("utf-8")
                self._password_attempts += 1
                return self._sudo_password
        else:
            # CLI mode - use getpass for secure input
            try:
                import sys

                if sys.stdin.isatty():
                    password = getpass.getpass("Enter sudo password: ")
                    if password:
                        self._sudo_password = password.encode("utf-8")
                        self._password_attempts += 1
                        return self._sudo_password
                else:
                    logger.error("No terminal available for password input")
            except Exception as e:
                logger.error(f"Failed to get password: {e}")

        return None

    def execute(
        self,
        command: List[str],
        sudo: bool = False,
        shell: bool = False,
        timeout: Optional[int] = None,
    ) -> bool:
        """Executes a command with optional sudo, shell, and timeout parameters.

        Args:
            command: Command and arguments as list of strings
            sudo: Whether to run with sudo
            shell: Whether to use shell execution
            timeout: Command timeout in seconds

        Returns:
            True if command succeeded, False otherwise
        """
        input_data = None
        if sudo:
            if not check_command_exists("sudo"):
                logger.error("Sudo command not found, cannot execute privileged task.")
                return False

            # Check if we already have sudo privileges
            has_sudo = (
                subprocess.call(
                    ["sudo", "-n", "-v"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                == 0
            )

            if has_sudo:
                full_command = ["sudo"] + command
            else:
                password = self._get_sudo_password()
                if password:
                    # Use sudo with askpass for more secure password handling
                    askpass_script = self._create_askpass_script(password)
                    if askpass_script:
                        env = os.environ.copy()
                        env["SUDO_ASKPASS"] = askpass_script
                        full_command = ["sudo", "-A", "-p", ""] + command
                        # Clean up the temporary askpass script after use
                        try:
                            result = self._execute_with_env(
                                full_command, env, shell, timeout
                            )
                            os.unlink(askpass_script)
                            return result
                        except Exception:
                            try:
                                os.unlink(askpass_script)
                            except OSError:
                                pass
                            return False
                    else:
                        # Fallback to stdin method (less secure)
                        full_command = ["sudo", "-S", "-p", ""] + command
                        input_data = password + b"\n"
                else:
                    # Fallback to non-interactive fail if no password provided
                    full_command = ["sudo", "-n"] + command
        else:
            full_command = command

        command_str = (
            " ".join(full_command)
            if not shell
            else full_command[0]
            if full_command
            else ""
        )

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {command_str}")
            return True

        try:
            subprocess.run(
                full_command, shell=shell, check=True, timeout=timeout, input=input_data
            )
            return True
        except subprocess.CalledProcessError as error:
            logger.error(f"Command failed ({command_str}): {error}")
        except FileNotFoundError:
            logger.error(f"Command not found: {command_str}")
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command_str}")
        except Exception as error:
            logger.error(f"Unexpected error running command ({command_str}): {error}")
        return False

    def _create_askpass_script(self, password: bytes) -> Optional[str]:
        """Creates a temporary askpass script for sudo -A."""
        try:
            import tempfile

            fd, path = tempfile.mkstemp(prefix="sudo_askpass_", text=True)
            with os.fdopen(fd, "w") as f:
                f.write(f"""#!/bin/sh
echo '{password.decode("utf-8", errors="ignore")}'
""")
            os.chmod(path, 0o700)
            return path
        except Exception as e:
            logger.warning(f"Failed to create askpass script: {e}")
            return None

    def _execute_with_env(
        self,
        command: List[str],
        env: Dict[str, str],
        shell: bool,
        timeout: Optional[int],
    ) -> bool:
        """Executes command with custom environment."""
        command_str = " ".join(command)
        try:
            subprocess.run(command, shell=shell, check=True, timeout=timeout, env=env)
            return True
        except subprocess.CalledProcessError as error:
            logger.error(f"Command failed ({command_str}): {error}")
            return False
        except Exception as error:
            logger.error(f"Unexpected error: {error}")
            return False

    def cleanup(self) -> None:
        """Cleans up resources, including passwords."""
        self._clear_password()


class SystemDetector:
    """Utilities for detecting operating system and package manager."""

    @staticmethod
    def detect_operating_system() -> str:
        """Detects the operating system by examining /etc/os-release.

        Returns:
            Operating system name as string
        """
        try:
            os_release_path = Path("/etc/os-release")
            if os_release_path.exists():
                with os_release_path.open() as file:
                    for line in file:
                        if line.startswith("PRETTY_NAME="):
                            return line.strip().split("=", 1)[1].strip('"')
        except Exception as error:
            logger.warning(f"Failed OS detection: {error}")

        # Fallback detection based on package managers
        if check_command_exists("pacman"):
            return "Arch Linux"
        elif check_command_exists("apt"):
            return "Ubuntu/Debian"
        else:
            return "Unknown Linux"

    @staticmethod
    def get_package_manager() -> str:
        """Identifies the system's package manager.

        Returns:
            Package manager name ('apt', 'pacman', or 'unknown')
        """
        if check_command_exists("apt"):
            return "apt"
        elif check_command_exists("pacman"):
            return "pacman"
        else:
            return "unknown"


class PackageCleaner:
    """Handles cleanup of orphaned packages and package caches."""

    def __init__(self, executor: CommandExecutor, package_manager: str) -> None:
        self.executor = executor
        self.package_manager = package_manager

    def clean_orphaned_packages(self) -> None:
        """Cleans orphaned packages specific to the detected package manager."""
        log_step("Cleaning Orphaned Packages")

        if self.package_manager == "apt":
            if self.executor.dry_run:
                logger.info("Simulating orphaned package removal (Dry Run):")
                try:
                    result = subprocess.run(
                        ["apt", "autoremove", "--purge", "--dry-run"],
                        capture_output=True,
                        text=True,
                        check=True,  # Changed to check=True to catch errors
                    )
                    if result.stdout:
                        logger.info(result.stdout.strip())
                    if result.stderr:
                        logger.warning(result.stderr.strip())
                except subprocess.CalledProcessError as error:
                    logger.error(
                        f"APT simulation failed with exit code {error.returncode}: {error.stderr}"
                    )
                except Exception as error:
                    logger.error(f"APT simulation failed: {error}")
            else:
                self.executor.execute(["apt", "autoremove", "--purge", "-y"], sudo=True)

        elif self.package_manager == "pacman":
            try:
                result = subprocess.run(
                    ["pacman", "-Qtdq"], capture_output=True, text=True, check=False
                )
                orphaned_packages = [
                    pkg for pkg in result.stdout.strip().split("\n") if pkg
                ]

                if not orphaned_packages:
                    logger.info("No orphaned packages found")
                    return

                logger.info(f"Orphaned packages found: {', '.join(orphaned_packages)}")

                if not self.executor.dry_run:
                    response = safe_input(
                        "Remove the orphaned packages?",
                        ["y", "n", ""],
                        default="n",
                    )
                    if response == "y":
                        for package in orphaned_packages:
                            self.executor.execute(
                                ["pacman", "-Rns", "--noconfirm", package], sudo=True
                            )
                        logger.info("Orphaned packages removed")
                    else:
                        logger.info("Skipped orphaned packages removal")
            except Exception as error:
                logger.error(f"Error during orphaned package cleanup: {error}")

        else:
            logger.error(
                f"Unsupported package manager for orphan cleaning: {self.package_manager}"
            )

    def clean_package_cache(self) -> None:
        """Cleans the package cache for the detected package manager."""
        log_step("Cleaning Package Cache")

        if self.package_manager == "apt":
            if self.executor.dry_run:
                logger.info(
                    "[DRY-RUN] Would clean APT package cache (autoclean + clean)"
                )
            else:
                self.executor.execute(["apt", "autoclean"], sudo=True)
                self.executor.execute(["apt", "clean"], sudo=True)

        elif self.package_manager == "pacman":
            try:
                # Preview what would be cleaned
                result = subprocess.run(
                    ["pacman", "-Sc", "--print-format", "%n %v"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                cache_info = result.stdout.strip()

                if cache_info:
                    logger.info(f"Package cache detected:\n{cache_info}")
                else:
                    logger.info("No package cache to clean")
                    return

                if not self.executor.dry_run:
                    response = safe_input(
                        "Clean package cache?", ["y", "n", ""], default="n"
                    )
                    if response == "y":
                        self.executor.execute(
                            ["pacman", "-Sc", "--noconfirm"], sudo=True
                        )
                        logger.info("Package cache cleaned")
                    else:
                        logger.info("Skipped package cache cleaning")
                else:
                    logger.info("[DRY-RUN] Would clean package cache")
            except Exception as error:
                logger.error(f"Error during package cache cleaning: {error}")

        else:
            logger.error(
                f"Unsupported package manager for cache cleaning: {self.package_manager}"
            )


class ConfigCleaner:
    """Handles cleanup of old backup configuration files."""

    def __init__(self, executor: CommandExecutor, package_manager: str) -> None:
        self.executor = executor
        self.package_manager = package_manager

    def find_old_configuration_files(self) -> List[Path]:
        """Finds old configuration files based on package manager patterns.

        Returns:
            List of Path objects pointing to old configuration files
        """
        logger.info("Searching for old configuration files")

        patterns = {
            "apt": ["*.dpkg-old", "*.dpkg-dist"],
            "pacman": ["*.pacsave", "*.pacnew"],
        }

        config_files = []

        if self.package_manager not in patterns:
            logger.warning(
                f"No config cleanup rules for package manager: {self.package_manager}"
            )
            return config_files

        try:
            for pattern in patterns[self.package_manager]:
                config_files.extend(Path("/etc").rglob(pattern))
        except Exception as error:
            logger.error(f"Error searching configuration files: {error}")

        # Remove duplicates but keep all files (removed arbitrary 30-file limit)
        return list(set(config_files))

    def clean_old_configurations(self) -> None:
        """Cleans old configuration files with user confirmation."""
        log_step("Cleaning Old Configurations")

        config_files = self.find_old_configuration_files()

        if not config_files:
            logger.info("No old configuration files found")
            return

        logger.info(f"Old configuration files found ({len(config_files)}):")
        for file_path in config_files[:50]:  # Show first 50 files only
            logger.info(f"  {file_path}")
        if len(config_files) > 50:
            logger.info(f"  ... and {len(config_files) - 50} more files")

        logger.warning(
            "IMPORTANT: Some .pacnew and .pacsave files may contain important updates."
        )
        logger.warning("Review carefully before removing.")

        if self.executor.dry_run:
            logger.info("[DRY-RUN] Would prompt to remove old configuration files")
            return

        response = safe_input(
            "Remove ANY old configuration files?", ["y", "n", ""], default="n"
        )

        if response != "y":
            logger.info("Keeping all old configuration files")
            return

        confirm = safe_input(
            "ARE YOU SURE? Type YES to confirm removal: ",
            ["yes", "no", ""],
            default="no",
        )

        if confirm != "yes":
            logger.info("Cancelled configuration files removal")
            return

        for file_path in config_files:
            if file_path.exists():
                try:
                    self.executor.execute(
                        ["rm", "-v", sanitize_path(str(file_path))], sudo=True
                    )
                except Exception as error:
                    logger.error(f"Failed to remove {file_path}: {error}")
            else:
                logger.warning(f"File already removed or missing: {file_path}")

        logger.info("Configuration files cleanup completed")


class AppConfigCleaner:
    """Handles cleanup of orphaned application configuration directories."""

    def __init__(
        self, executor: CommandExecutor, package_manager: str, deep_scan: bool = False
    ) -> None:
        self.executor = executor
        self.package_manager = package_manager
        self.deep_scan = deep_scan
        self._deep_scan_cache: Optional[Set[str]] = None
        self._flatpak_packages_cache: Optional[List[str]] = None
        self._snap_packages_cache: Optional[List[str]] = None
        self._installed_packages_cache: Optional[List[str]] = None
        self._installed_packages_lower_cache: Optional[Set[str]] = None

    def get_installed_packages(self) -> List[str]:
        """Retrieves list of currently installed packages.

        Returns:
            List of installed package names
        """
        if self._installed_packages_cache is not None:
            return self._installed_packages_cache

        try:
            if self.package_manager == "apt":
                result = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Package}\\n"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            elif self.package_manager == "pacman":
                result = subprocess.run(
                    ["pacman", "-Qq"], capture_output=True, text=True, check=True
                )
            else:
                self._installed_packages_cache = []
                return []

            packages = result.stdout.strip().split("\n")
            self._installed_packages_cache = packages
            return packages

        except Exception as error:
            logger.error(f"Error retrieving installed packages: {error}")
            self._installed_packages_cache = []
            return []

    def _get_installed_packages_lower(self) -> Set[str]:
        """Gets installed packages as lowercase set for efficient matching."""
        if self._installed_packages_lower_cache is not None:
            return self._installed_packages_lower_cache

        packages = self.get_installed_packages()
        self._installed_packages_lower_cache = {pkg.lower() for pkg in packages}
        return self._installed_packages_lower_cache

    def get_flatpak_packages(self) -> List[str]:
        """Retrieves list of currently installed Flatpak packages."""
        if self._flatpak_packages_cache is not None:
            return self._flatpak_packages_cache

        if not check_command_exists("flatpak"):
            self._flatpak_packages_cache = []
            return []

        try:
            logger.info("Checking for Flatpak packages...")
            result = subprocess.run(
                ["flatpak", "list", "--app", "--columns=application"],
                capture_output=True,
                text=True,
                check=True,
            )
            packages = result.stdout.strip().split("\n")

            processed_packages = []
            for pkg in packages:
                if pkg:
                    processed_packages.append(pkg.lower())
                    # Add app name for better matching, e.g., 'gimp' from 'org.gimp.GIMP'
                    if "." in pkg:
                        processed_packages.append(pkg.split(".")[-1].lower())

            self._flatpak_packages_cache = list(set(processed_packages))
            return self._flatpak_packages_cache
        except Exception as error:
            logger.warning(f"Error retrieving Flatpak packages: {error}")
            self._flatpak_packages_cache = []
            return []

    def get_snap_packages(self) -> List[str]:
        """Retrieves list of currently installed Snap packages."""
        if self._snap_packages_cache is not None:
            return self._snap_packages_cache

        if not check_command_exists("snap"):
            self._snap_packages_cache = []
            return []

        try:
            logger.info("Checking for Snap packages...")
            result = subprocess.run(
                ["snap", "list"], capture_output=True, text=True, check=True
            )
            lines = result.stdout.strip().split("\n")

            if not lines or "no snaps" in lines[0].lower():
                self._snap_packages_cache = []
                return []

            # Skip header line 'Name Version Rev Tracking Publisher Notes'
            packages = [line.split()[0] for line in lines[1:] if line]
            self._snap_packages_cache = [pkg.lower() for pkg in packages]
            return self._snap_packages_cache
        except Exception as error:
            logger.warning(f"Error retrieving Snap packages: {error}")
            self._snap_packages_cache = []
            return []

    def _get_deep_scan_files(self) -> Set[str]:
        """Scans home directory for potential application files."""
        if self._deep_scan_cache is not None:
            return self._deep_scan_cache

        logger.info("Performing deep scan of home directory for applications...")
        files_found = set()
        home = Path.home()
        exclude_dirs = {".cache", ".config", ".local", ".git", "__pycache__"}

        for root, dirs, files in os.walk(home):
            dirs[:] = [
                d for d in dirs if d not in exclude_dirs and not d.startswith(".")
            ]
            for file in files:
                file_path = os.path.join(root, file)
                # Check for AppImages or executable files
                if file.lower().endswith(".appimage") or os.access(file_path, os.X_OK):
                    files_found.add(file.lower())

        # Explicitly scan ~/.local/bin which is otherwise excluded
        local_bin = home / ".local" / "bin"
        if local_bin.exists():
            for root, _, files in os.walk(local_bin):
                for file in files:
                    if os.access(os.path.join(root, file), os.X_OK):
                        files_found.add(file.lower())

        self._deep_scan_cache = files_found
        return self._deep_scan_cache

    def _is_package_installed(self, item_name: str, item_path: Path) -> bool:
        """Checks if a directory corresponds to an installed package."""
        item_lower = item_name.lower()
        installed_lower = self._get_installed_packages_lower()

        # 1. Exact match (case-insensitive)
        if item_lower in installed_lower:
            return True

        # 2. Common pattern: package "python-foo" creates dir "foo"
        for pkg in installed_lower:
            if "-" in pkg and item_lower == pkg.split("-", 1)[-1]:
                return True
            # Handle lib prefixes
            if pkg.startswith("lib") and item_lower == pkg[3:]:
                return True

        # 3. Check if command exists in PATH (only check once)
        if check_command_exists(item_name) or check_command_exists(item_lower):
            return True

        # 4. Deep Scan checks
        if self.deep_scan:
            # Check Flatpak packages
            flatpak_packages = self.get_flatpak_packages()
            if flatpak_packages and item_lower in flatpak_packages:
                return True

            # Check Snap packages
            snap_packages = self.get_snap_packages()
            if snap_packages and item_lower in snap_packages:
                return True

            # Check for AppImages/binaries
            deep_files = self._get_deep_scan_files()
            if item_lower in deep_files:
                return True

            # Fuzzy match for versioned AppImages/binaries
            for file_name in deep_files:
                if file_name.startswith(item_lower):
                    remainder = file_name[len(item_lower) :]
                    if not remainder or remainder[0] in ("-", ".", "_"):
                        return True

        return False

    def _calculate_directory_size(self, directory: Path) -> int:
        """Calculates directory size efficiently."""
        try:
            # Use du command for large directories (more efficient)
            if directory.is_dir():
                result = subprocess.run(
                    ["du", "-sb", str(directory)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    size_str = result.stdout.split()[0]
                    return int(size_str)

            # Fallback to Python method
            total_size = 0
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    try:
                        total_size += file_path.stat().st_size
                    except (OSError, PermissionError):
                        continue
            return total_size
        except Exception:
            return 0

    def find_orphaned_configurations(self) -> List[Tuple[Path, int]]:
        """Scans configuration directories for folders not matching installed packages.

        Returns:
            List of tuples (path, size_bytes) for orphaned configurations
        """
        config_directories = [
            Path.home() / ".config",
            Path.home() / ".local" / "share",
            Path.home() / ".local" / "bin",
            Path.home() / ".local" / "lib",
            Path.home() / ".cache",
        ]

        orphaned_configs = []

        skip_directories = {
            "applications",
            "autostart",
            "desktop",
            "documents",
            "downloads",
            "fonts",
            "icons",
            "mime",
            "music",
            "pictures",
            "public",
            "templates",
            "themes",
            "videos",
        }

        for root_directory in config_directories:
            if not root_directory.exists():
                continue

            try:
                items = list(root_directory.iterdir())
                total_items = len(items)
                processed = 0

                for item in items:
                    processed += 1
                    if processed % 20 == 0:  # Log progress every 20 items
                        logger.info(
                            f"  Scanning {root_directory}: {processed}/{total_items} items..."
                        )

                    if (
                        not item.is_dir()
                        or item.name.lower() in skip_directories
                        or len(item.name) <= 2
                    ):
                        continue

                    if not self._is_package_installed(item.name, item):
                        size_bytes = self._calculate_directory_size(item)
                        orphaned_configs.append((item, size_bytes))

            except Exception as error:
                logger.warning(f"Could not scan {root_directory}: {error}")

        return orphaned_configs

    def clean_orphaned_configurations(self) -> None:
        """Identifies and optionally removes orphaned application configurations."""
        log_step("Cleaning App Configurations")

        orphaned_configs = self.find_orphaned_configurations()

        if not orphaned_configs:
            logger.info("No orphaned application configurations found")
            return

        total_size_bytes = 0
        logger.info("Potential orphaned application configurations found:")

        for path, size_bytes in orphaned_configs:
            size_str = format_size_bytes(size_bytes)
            logger.info(f"  {path} ({size_str})")
            total_size_bytes += size_bytes

        logger.info(f"Total size: {format_size_bytes(total_size_bytes)}")
        logger.warning(
            "These may be from removed or manually installed applications. "
            "Review carefully as there may be false positives."
        )

        if self.executor.dry_run:
            logger.info("[DRY-RUN] Would prompt to remove orphaned configurations")
            return

        response = safe_input(
            "Remove any of these configurations?", ["y", "n", ""], default="n"
        )
        if response != "y":
            logger.info("Keeping all orphaned configurations")
            return

        for path, _ in orphaned_configs:
            if path.exists():
                response = safe_input(f"Remove {path}?", ["y", "n", ""], default="n")
                if response == "y":
                    try:
                        self.executor.execute(
                            ["rm", "-rf", sanitize_path(str(path))], sudo=False
                        )
                        logger.info(f"Removed {path}")
                    except Exception as error:
                        logger.error(f"Failed to remove {path}: {error}")
                else:
                    logger.info(f"Kept {path}")

    def clear_caches(self) -> None:
        """Clears internal caches to free memory."""
        self._deep_scan_cache = None
        self._flatpak_packages_cache = None
        self._snap_packages_cache = None
        self._installed_packages_cache = None
        self._installed_packages_lower_cache = None


class SystemCacheCleaner:
    """Handles cleanup of system caches and user wastebasket."""

    def __init__(self, executor: CommandExecutor) -> None:
        self.executor = executor
        self.current_user = getpass.getuser()

    def clean_system_cache(self) -> None:
        """Cleans system temporary files in /tmp older than 7 days."""
        log_step("Cleaning System Cache")

        if self.executor.dry_run:
            logger.info("[DRY-RUN] Would clean /tmp files older than 7 days")
            return

        response = safe_input(
            "Clean system temporary files in /tmp?",
            ["y", "n", ""],
            default="n",
        )
        if response != "y":
            logger.info("Skipped system temporary files cleaning")
            return

        # Safety check: ensure we're actually cleaning /tmp
        tmp_real = Path("/tmp").resolve()
        if str(tmp_real) != "/tmp":
            logger.warning(f"/tmp resolves to {tmp_real}, aborting for safety")
            return

        self.executor.execute(
            [
                "find",
                "/tmp",
                "-xdev",
                "-type",
                "f",
                "!",
                "-name",
                ".*",
                "-atime",
                "+7",
                "-delete",
            ],
            sudo=True,
        )

    def clean_user_wastebasket(self) -> None:
        """Empties the trash/wastebasket for the current user."""
        log_step(f"Cleaning Wastebasket for user '{self.current_user}'")

        if self.executor.dry_run:
            logger.info(
                f"[DRY-RUN] Would clean wastebasket for user {self.current_user}"
            )
            return

        response = safe_input(
            f"Clean wastebasket (empty trash) for user {self.current_user}?",
            ["y", "n", ""],
            default="n",
        )
        if response != "y":
            logger.info("Skipped wastebasket cleaning")
            return

        wastebasket_locations = [
            ".local/share/Trash/files",
            ".local/share/Trash/info",
            ".Trash",
            ".trash",
            ".kde/share/apps/trash",
        ]

        user_home = Path.home()
        total_removed = 0
        found_locations = False

        for location in wastebasket_locations:
            trash_path = user_home / location

            if not trash_path.exists():
                continue

            found_locations = True

            try:
                items = list(trash_path.iterdir())
                total_removed += len(items)
                for item in items:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                logger.info(f"Cleaned wastebasket at {trash_path}")
            except Exception as error:
                logger.warning(f"Cannot clean {trash_path}: {error}")

        if not found_locations:
            logger.info("No wastebasket locations found for current user")
        else:
            logger.info(
                f"Wastebasket cleaned for {self.current_user}, "
                f"total items removed: {total_removed}"
            )


class SystemCleanup:
    """Orchestrates the complete system cleanup process."""

    def __init__(self, dry_run: bool = True, deep_scan: bool = False) -> None:
        self.dry_run = dry_run
        self.deep_scan = deep_scan
        self.executor = CommandExecutor(dry_run=dry_run)
        self.distribution = SystemDetector.detect_operating_system()
        self.package_manager = SystemDetector.get_package_manager()
        self.package_cleaner = PackageCleaner(self.executor, self.package_manager)
        self.config_cleaner = ConfigCleaner(self.executor, self.package_manager)
        self.app_config_cleaner = AppConfigCleaner(
            self.executor, self.package_manager, deep_scan
        )
        self.cache_cleaner = SystemCacheCleaner(self.executor)

    def show_disk_usage(self) -> None:
        """Logs current disk usage for important mount points."""
        logger.info("Current disk usage:")

        try:
            result = subprocess.run(
                ["df", "-h"], capture_output=True, text=True, check=True
            )
            lines = result.stdout.strip().split("\n")
            logger.info(lines[0])  # Header line

            important_mounts = ["/", "/home", "/boot", "/var", "/tmp"]
            shown_filesystems = set()

            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    mount_point = parts[5]
                    filesystem = parts[0]

                    if (
                        mount_point in important_mounts
                        and filesystem not in shown_filesystems
                    ):
                        logger.info(line)
                        shown_filesystems.add(filesystem)

            # Always show root filesystem if not already shown
            if not shown_filesystems:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[5] == "/":
                        logger.info(line)
                        break
        except Exception as error:
            logger.error(f"Failed to retrieve disk usage info: {error}")

    def run(self, tasks: Dict[str, bool]) -> None:
        """Executes selected cleanup tasks in sequence.

        Args:
            tasks: Dictionary mapping task names to boolean enable flags
        """
        logger.info("Starting system cleanup script")
        logger.info(f"Detected OS: {self.distribution}")
        logger.info(f"Package manager: {self.package_manager}")

        if self.package_manager == "unknown":
            logger.error("Unsupported package manager. Exiting.")
            return

        if self.dry_run:
            logger.info("Running in dry-run mode (no changes will be made)")
        else:
            logger.warning("Running in real cleanup mode - changes will be made")

        self.show_disk_usage()

        # Execute enabled tasks
        if tasks.get("orphaned_packages"):
            self.package_cleaner.clean_orphaned_packages()

        if tasks.get("package_cache"):
            self.package_cleaner.clean_package_cache()

        if tasks.get("old_configs"):
            self.config_cleaner.clean_old_configurations()

        if tasks.get("app_configs"):
            self.app_config_cleaner.clean_orphaned_configurations()

        if tasks.get("system_cache"):
            self.cache_cleaner.clean_system_cache()

        if tasks.get("wastebasket"):
            self.cache_cleaner.clean_user_wastebasket()

        # Clear caches to free memory
        self.app_config_cleaner.clear_caches()

        self.show_disk_usage()
        logger.info("System cleanup completed")

        if self.dry_run:
            logger.info("This was a dry-run. No changes were made.")

        # Cleanup resources
        self.executor.cleanup()


# ==============================================================================
# GUI COMPONENTS
# ==============================================================================


class GMessageBox:
    """Custom message box with consistent font sizing."""

    @staticmethod
    def _draw_icon(canvas: tk.Canvas, icon: str) -> None:
        """Draws the specified icon onto the canvas."""
        # Use text characters for shapes to ensure antialiasing on all platforms
        # Circle: ● (U+25CF), Triangle: ▲ (U+25B2)

        font_family = "Segoe UI" if os.name == "nt" else "Helvetica"

        if icon == "information":
            # Blue circle with 'i'
            canvas.create_text(28, 28, text="●", fill="#0078D7", font=(font_family, 72))
            canvas.create_text(
                28, 28, text="i", fill="white", font=(font_family, 22, "bold")
            )
        elif icon == "warning":
            # Yellow triangle with '!'
            canvas.create_text(28, 28, text="▲", fill="#FFC107", font=(font_family, 64))
            canvas.create_text(
                28, 30, text="!", fill="black", font=(font_family, 22, "bold")
            )
        elif icon == "error":
            # Red circle with 'X'
            canvas.create_text(28, 28, text="●", fill="#E81123", font=(font_family, 72))
            canvas.create_text(
                28, 28, text="X", fill="white", font=(font_family, 20, "bold")
            )
        elif icon == "question":
            # Blue circle with '?'
            canvas.create_text(28, 28, text="●", fill="#0078D7", font=(font_family, 72))
            canvas.create_text(
                28, 28, text="?", fill="white", font=(font_family, 22, "bold")
            )

    @staticmethod
    def _create_dialog(
        title: str,
        message: str,
        buttons: List[tuple],
        icon: Optional[str] = None,
        rich_text: bool = False,
    ) -> Any:
        dialog = tk.Toplevel()
        root = dialog.master
        dialog.title(title)
        if root:
            dialog.transient(cast(tk.Wm, root))
        dialog.grab_set()
        dialog.resizable(False, False)

        # Use consistent font styling
        font_family = "Segoe UI" if os.name == "nt" else "Helvetica"
        font_size = 9 if os.name == "nt" else 10
        font_style = (font_family, font_size)

        # Get dialog background color
        bg_color = ttk.Style().lookup("TFrame", "background") or "#f0f0f0"

        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        if icon:
            icon_canvas = tk.Canvas(
                content_frame,
                width=56,
                height=56,
                highlightthickness=0,
                bg=bg_color,
            )
            icon_canvas.pack(side=tk.LEFT, anchor=tk.N, padx=(0, 15))
            GMessageBox._draw_icon(icon_canvas, icon)

        if rich_text:
            # Calculate appropriate height based on content
            plain_message = message
            for tag in [
                "<b>",
                "</b>",
                "<i>",
                "</i>",
                "<u>",
                "</u>",
                "<red>",
                "</red>",
                "<blue>",
                "</blue>",
                "<green>",
                "</green>",
            ]:
                plain_message = plain_message.replace(tag, "")

            # Estimate height: ~40 characters per line, min 3 lines, max 10 lines
            estimated_height = min(max(len(plain_message) // 40 + 1, 3), 10)

            # Use Text widget for rich text support
            text_widget = tk.Text(
                content_frame,
                font=font_style,
                wrap=tk.WORD,
                width=40,
                height=estimated_height,
                relief=tk.FLAT,
                borderwidth=0,
                padx=0,
                pady=0,
                bg=bg_color,
                selectbackground=bg_color,
                inactiveselectbackground=bg_color,
                highlightthickness=0,
                exportselection=False,
            )
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            # Configure tags for formatting
            text_widget.tag_configure("bold", font=(font_family, font_size, "bold"))
            text_widget.tag_configure("italic", font=(font_family, font_size, "italic"))
            text_widget.tag_configure(
                "underline", font=(font_family, font_size, "normal", "underline")
            )
            text_widget.tag_configure("red", foreground="#E81123")
            text_widget.tag_configure("blue", foreground="#0078D7")
            text_widget.tag_configure("green", foreground="#107C10")

            # Rich text markup parsing with state tracking
            i = 0
            bold_on = False
            italic_on = False
            underline_on = False
            red_on = False
            blue_on = False
            green_on = False

            while i < len(message):
                if message.startswith("<b>", i):
                    bold_on = True
                    i += 3
                    continue
                elif message.startswith("</b>", i):
                    bold_on = False
                    i += 4
                    continue
                elif message.startswith("<i>", i):
                    italic_on = True
                    i += 3
                    continue
                elif message.startswith("</i>", i):
                    italic_on = False
                    i += 4
                    continue
                elif message.startswith("<u>", i):
                    underline_on = True
                    i += 3
                    continue
                elif message.startswith("</u>", i):
                    underline_on = False
                    i += 4
                    continue
                elif message.startswith("<red>", i):
                    red_on = True
                    i += 5
                    continue
                elif message.startswith("</red>", i):
                    red_on = False
                    i += 6
                    continue
                elif message.startswith("<blue>", i):
                    blue_on = True
                    i += 6
                    continue
                elif message.startswith("</blue>", i):
                    blue_on = False
                    i += 7
                    continue
                elif message.startswith("<green>", i):
                    green_on = True
                    i += 7
                    continue
                elif message.startswith("</green>", i):
                    green_on = False
                    i += 8
                    continue
                else:
                    # Insert character with current formatting
                    tags = []
                    if bold_on:
                        tags.append("bold")
                    if italic_on:
                        tags.append("italic")
                    if underline_on:
                        tags.append("underline")
                    if red_on:
                        tags.append("red")
                    if blue_on:
                        tags.append("blue")
                    if green_on:
                        tags.append("green")

                    text_widget.insert(tk.END, message[i], tuple(tags) if tags else ())
                    i += 1

            text_widget.config(state=tk.DISABLED)
        else:
            label = ttk.Label(
                content_frame,
                text=message,
                font=font_style,
                wraplength=350,
                justify=tk.LEFT,
            )
            label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Button setup
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        container = ttk.Frame(btn_frame)
        container.pack(anchor=tk.CENTER)
        result = None

        def on_btn(value):
            nonlocal result
            result = value
            dialog.destroy()

        # Create buttons
        for text, value, default in buttons:
            btn = ttk.Button(
                container,
                text=text,
                command=lambda v=value: on_btn(v),
                width=10,
                cursor="hand2",
            )
            btn.pack(side=tk.LEFT, padx=5)
            if default:
                btn.focus_set()
                dialog.bind("<Return>", lambda e, v=value: on_btn(v))

        # Keyboard shortcuts
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        # Center dialog
        dialog.update_idletasks()
        if root:
            x = root.winfo_x() + (root.winfo_width() - dialog.winfo_reqwidth()) // 2
            y = root.winfo_y() + (root.winfo_height() - dialog.winfo_reqheight()) // 2
            dialog.geometry(f"+{x}+{y}")

        dialog.wait_window()
        return result

    @staticmethod
    def showinfo(title: str, message: str, rich_text: bool = False) -> None:
        GMessageBox._create_dialog(
            title,
            message,
            [("OK", None, True)],
            icon="information",
            rich_text=rich_text,
        )

    @staticmethod
    def showwarning(title: str, message: str, rich_text: bool = False) -> None:
        GMessageBox._create_dialog(
            title, message, [("OK", None, True)], icon="warning", rich_text=rich_text
        )

    @staticmethod
    def showerror(title: str, message: str, rich_text: bool = False) -> None:
        GMessageBox._create_dialog(
            title, message, [("OK", None, True)], icon="error", rich_text=rich_text
        )

    @staticmethod
    def askyesno(title: str, message: str, rich_text: bool = False) -> Optional[bool]:
        return GMessageBox._create_dialog(
            title,
            message,
            [("Yes", True, True), ("No", False, False)],
            icon="question",
            rich_text=rich_text,
        )

    @staticmethod
    def showinfo_rich(title: str, message: str) -> None:
        """Show info dialog with rich text formatting."""
        GMessageBox.showinfo(title, message, rich_text=True)

    @staticmethod
    def showwarning_rich(title: str, message: str) -> None:
        """Show warning dialog with rich text formatting."""
        GMessageBox.showwarning(title, message, rich_text=True)

    @staticmethod
    def showerror_rich(title: str, message: str) -> None:
        """Show error dialog with rich text formatting."""
        GMessageBox.showerror(title, message, rich_text=True)

    @staticmethod
    def askyesno_rich(title: str, message: str) -> Optional[bool]:
        """Show question dialog with rich text formatting."""
        return GMessageBox.askyesno(title, message, rich_text=True)

    @staticmethod
    def askpassword(title: str, message: str) -> Optional[str]:
        """Show password input dialog with secure entry field."""
        dialog = tk.Toplevel()
        root = dialog.master
        dialog.title(title)
        if root:
            dialog.transient(cast(tk.Wm, root))
        dialog.grab_set()
        dialog.resizable(False, False)

        # Use consistent font styling
        font_family = "Segoe UI" if os.name == "nt" else "Helvetica"
        font_size = 9 if os.name == "nt" else 10
        font_style = (font_family, font_size)

        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Message label
        ttk.Label(main_frame, text=message, font=font_style, wraplength=300).pack(
            fill=tk.X, pady=(0, 10)
        )

        # Password entry field
        password_var = tk.StringVar()
        entry = ttk.Entry(main_frame, show="*", textvariable=password_var, width=30)
        entry.pack(fill=tk.X, pady=(0, 20))
        entry.focus_set()

        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        container = ttk.Frame(btn_frame)
        container.pack(anchor=tk.CENTER)

        result = None

        def on_ok():
            nonlocal result
            result = password_var.get()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        # OK and Cancel buttons
        ttk.Button(container, text="OK", command=on_ok, width=10, cursor="hand2").pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(
            container, text="Cancel", command=on_cancel, width=10, cursor="hand2"
        ).pack(side=tk.LEFT, padx=5)

        # Keyboard shortcuts
        dialog.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: on_cancel())

        # Center dialog on parent window
        dialog.update_idletasks()
        if root:
            x = root.winfo_x() + (root.winfo_width() - dialog.winfo_reqwidth()) // 2
            y = root.winfo_y() + (root.winfo_height() - dialog.winfo_reqheight()) // 2
            dialog.geometry(f"+{x}+{y}")

        dialog.wait_window()
        return result


class GuiInputHandler:
    """Handles user input requests via GUI dialogs in thread-safe manner."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.result = None
        self.event = threading.Event()
        self.timeout = 30  # seconds

    def request(
        self, prompt: str, valid_responses: List[str], default: Optional[str] = None
    ) -> Optional[str]:
        """Requests input from user via modal dialog.

        Args:
            prompt: Question to ask user
            valid_responses: List of acceptable responses
            default: Default response if user cancels

        Returns:
            User response or default
        """
        self.event.clear()
        self.result = None
        self.root.after(0, lambda: self._ask_dialog(prompt, valid_responses, default))

        # Wait with timeout
        if not self.event.wait(timeout=self.timeout):
            logger.warning(
                f"Input request timed out after {self.timeout} seconds, using default: {default}"
            )
            return default

        return self.result

    def request_password(self, title: str, prompt: str) -> Optional[str]:
        """Requests password from user via modal dialog."""
        self.event.clear()
        self.result = None
        self.root.after(0, lambda: self._ask_password_dialog(title, prompt))

        # Wait with timeout
        if not self.event.wait(timeout=self.timeout):
            logger.warning(f"Password request timed out after {self.timeout} seconds")
            return None

        return self.result

    def _ask_dialog(
        self, prompt: str, valid_responses: List[str], default: Optional[str]
    ) -> None:
        """Displays appropriate dialog based on response type."""
        try:
            is_confirmation = "yes" in valid_responses or "YES" in valid_responses

            if is_confirmation:
                answer = GMessageBox.askyesno("Confirmation Required", prompt)
                self.result = "yes" if answer else "no"
            else:
                # For simple yes/no questions
                if set(valid_responses) <= {"y", "n", ""}:
                    answer = GMessageBox.askyesno("Input Required", prompt)
                    self.result = "y" if answer else "n"
                else:
                    # For more complex choices, we need a custom dialog
                    # For now, use default
                    logger.warning(
                        f"Complex choices not yet supported: {valid_responses}"
                    )
                    self.result = default
        except Exception as error:
            logger.error(f"Error displaying dialog: {error}")
            self.result = default
        finally:
            self.event.set()

    def _ask_password_dialog(self, title: str, prompt: str) -> None:
        try:
            self.result = GMessageBox.askpassword(title, prompt)
        finally:
            self.event.set()


class QueueHandler(logging.Handler):
    """Logging handler that pushes records to queue for thread-safe GUI updates."""

    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        """Emits log record to queue for GUI processing."""
        message = self.format(record)
        self.log_queue.put(message)


class CleanupApp:
    """Main Tkinter application class for the System Cleanup Utility."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("System Cleanup Utility")

        # Load configuration
        self.config_file = Path(__file__).resolve().parent / "system_cleanup.json"
        self.config = self.load_config()

        geometry = self.config.get("geometry", "800x600")
        self.root.geometry(geometry)

        # Set global gui_input_handler immediately to avoid circular dependency
        global gui_input_handler
        gui_input_handler = GuiInputHandler(self.root)

        # Apply theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Bold.TButton", font=("", 10, "bold"))

        # Setup logging
        logging.addLevelName(logging.WARNING, "WARN")
        self.log_queue = queue.Queue()
        handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Initialize UI
        self.setup_user_interface()

        # Apply saved options
        self.apply_config_options()

        # Start log polling
        self.root.after(100, self.process_log_queue)

        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def load_config(self) -> Dict[str, Any]:
        """Loads configuration from JSON file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f)
            except Exception as error:
                logger.warning(f"Failed to load config: {error}")
        return {}

    def save_config(self) -> None:
        """Saves current configuration to JSON file."""
        config = {
            "geometry": self.root.geometry(),
            "deep_scan": self.deep_scan_var.get(),
            "tasks": {k: v.get() for k, v in self.tasks.items()},
        }
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=4)
        except Exception as error:
            logger.error(f"Failed to save config: {error}")

    def apply_config_options(self) -> None:
        """Applies loaded configuration to UI variables."""
        if not self.config:
            return

        if "deep_scan" in self.config:
            self.deep_scan_var.set(self.config["deep_scan"])

        if "tasks" in self.config:
            saved_tasks = self.config["tasks"]
            for task, value in saved_tasks.items():
                if task in self.tasks:
                    self.tasks[task].set(value)

    def on_close(self) -> None:
        """Handles application closure."""
        self.save_config()
        self.root.destroy()

    def setup_user_interface(self) -> None:
        """Sets up all GUI components and layout."""
        # Options Frame
        options_frame = ttk.LabelFrame(self.root, text="Cleanup Options", padding=10)
        options_frame.pack(fill="x", padx=10, pady=5)

        top_options_frame = ttk.Frame(options_frame)
        top_options_frame.pack(fill="x")

        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            top_options_frame,
            text="Dry Run (Simulate only)",
            variable=self.dry_run_var,
            command=self.on_dry_run_toggle,
        ).pack(side="left", padx=10, pady=5)

        self.deep_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top_options_frame,
            text="Deep Scan Mode (Slow)",
            variable=self.deep_scan_var,
        ).pack(side="left", padx=10, pady=5)

        ttk.Separator(options_frame, orient="horizontal").pack(fill="x", pady=5)

        # Task checkboxes
        self.tasks = {
            "orphaned_packages": tk.BooleanVar(value=True),
            "package_cache": tk.BooleanVar(value=True),
            "old_configs": tk.BooleanVar(value=True),
            "app_configs": tk.BooleanVar(value=True),
            "system_cache": tk.BooleanVar(value=True),
            "wastebasket": tk.BooleanVar(value=True),
        }

        task_frame = ttk.Frame(options_frame)
        task_frame.pack(fill="x")

        row = 0
        column = 0
        for task_key, task_var in self.tasks.items():
            label = task_key.replace("_", " ").title()
            ttk.Checkbutton(task_frame, text=label, variable=task_var).grid(
                row=row, column=column, sticky="w", padx=10, pady=5
            )
            column += 1
            if column > 2:
                column = 0
                row += 1

        # Button Frame
        button_frame = ttk.Frame(self.root, padding=5)
        button_frame.pack(side="bottom", fill="x")

        button_container = ttk.Frame(button_frame)
        button_container.pack(anchor="center")

        self.start_button = ttk.Button(
            button_container,
            text="Start",
            command=self.start_cleanup,
            width=11,
            cursor="hand2",
            style="Bold.TButton",
        )
        self.start_button.pack(side="left", padx=5, pady=5)

        ttk.Button(
            button_container,
            text="Exit",
            command=self.on_close,
            width=11,
            cursor="hand2",
            style="Bold.TButton",
        ).pack(side="left", padx=5, pady=5)

        # Log Area
        log_frame = ttk.LabelFrame(self.root, text="Log Output", padding=5)
        log_frame.pack(fill="both", expand=True, padx=10)

        self.log_text = tk.Text(
            log_frame,
            state="disabled",
            height=15,
            font=("Monospace", 10),
            wrap="none",
        )

        vertical_scrollbar = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.log_text.yview
        )
        horizontal_scrollbar = ttk.Scrollbar(
            log_frame, orient="horizontal", command=self.log_text.xview
        )

        self.log_text.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )

        self.log_text.grid(row=0, column=0, sticky="nsew")
        vertical_scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew")

        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)

        # Context Menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(
            label="Select All",
            command=lambda: self.log_text.tag_add("sel", "1.0", "end"),
        )
        self.context_menu.add_command(
            label="Copy", command=lambda: self.log_text.event_generate("<<Copy>>")
        )
        self.context_menu.add_command(label="Cut", command=self.perform_cut)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Clear", command=self.clear_log)

        self.log_text.bind("<Button-3>", self.show_context_menu)
        self.log_text.bind("<Escape>", lambda e: self.context_menu.unpost())

        # Configure text tags for colored output
        self.log_text.tag_config("INFO", foreground="black")
        self.log_text.tag_config("WARNING", foreground="#FF8C00")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("STEP", foreground="blue")

    def show_context_menu(self, event: tk.Event) -> None:
        """Displays context menu with actions disabled if log is empty."""
        has_content = bool(self.log_text.get("1.0", "end-1c"))
        state = "normal" if has_content else "disabled"

        self.context_menu.entryconfig("Copy", state=state)
        self.context_menu.entryconfig("Cut", state=state)
        self.context_menu.entryconfig("Select All", state=state)
        self.context_menu.entryconfig("Clear", state=state)

        self.context_menu.post(event.x_root, event.y_root)

    def process_log_queue(self) -> None:
        """Polls log queue and updates text widget with messages."""
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.log_text.configure(state="normal")

            # Determine appropriate tag based on message content
            tag = "INFO"
            if "WARN" in message:
                tag = "WARNING"
            elif "ERROR" in message:
                tag = "ERROR"
            elif "STEP" in message:
                tag = "STEP"

            self.log_text.insert(tk.END, message + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")

        self.root.after(100, self.process_log_queue)

    def perform_cut(self) -> None:
        """Performs cut operation on disabled text widget."""
        try:
            if not self.log_text.tag_ranges("sel"):
                return

            self.log_text.configure(state="normal")
            text = self.log_text.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log_text.delete("sel.first", "sel.last")
            self.log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def clear_log(self) -> None:
        """Clears the log output."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")

    def on_dry_run_toggle(self) -> None:
        """Warns user when dry run is disabled."""
        if not self.dry_run_var.get():
            GMessageBox.showwarning_rich(
                "Real Mode Activated",
                "<b>You have disabled Dry Run mode.</b>\n\n"
                "The script will now perform REAL changes to your system.\n"
                "Files will be deleted permanently.",
            )

    def start_cleanup(self) -> None:
        """Starts cleanup process in separate thread to keep GUI responsive."""
        self.start_button.config(state="disabled")

        # Clear log
        self.clear_log()

        dry_run = self.dry_run_var.get()
        deep_scan = self.deep_scan_var.get()
        selected_tasks = {key: var.get() for key, var in self.tasks.items()}

        cleanup_thread = threading.Thread(
            target=self.execute_cleanup_thread,
            args=(dry_run, deep_scan, selected_tasks),
        )
        cleanup_thread.daemon = True
        cleanup_thread.start()

    def execute_cleanup_thread(
        self, dry_run: bool, deep_scan: bool, selected_tasks: Dict[str, bool]
    ) -> None:
        """Executes cleanup logic in background thread."""
        try:
            cleanup = SystemCleanup(dry_run=dry_run, deep_scan=deep_scan)
            cleanup.run(selected_tasks)
        except Exception as error:
            logger.error(f"Critical error during cleanup: {error}")
        finally:
            self.root.after(0, lambda: self.start_button.config(state="normal"))


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================


def main() -> None:
    """Main entry point for the System Cleanup Utility."""
    root = tk.Tk()
    _app = CleanupApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
