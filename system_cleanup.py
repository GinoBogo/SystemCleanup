#!/usr/bin/env python3

"""
Robust System Cleanup Script for Arch Linux and Ubuntu

Improved error handling, input validation, dry-run mode, safe logging setup with
colorized console output including cyan step headers, permission checks,
concurrency and file operation safety, configurability, and modular well-typed
code.

Author: Gino Bogo
License: MIT
Version: 1.0
"""

import getpass
import logging
import os
import queue
import sys
import shutil
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Dict, List, Optional, Tuple, cast

# ==============================================================================
# GLOBAL CONSTANTS AND SETUP
# ==============================================================================

logger = logging.getLogger("system_cleanup")
logger.setLevel(logging.INFO)

gui_input_handler = None  # Global input handler for GUI mode


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================


def log_step(message: str) -> None:
    """Logs a message formatted as a processing step."""
    logger.info(f"--- STEP: {message} ---")


def safe_input(
    prompt: str, valid_responses: List[str], default: Optional[str] = None
) -> str:
    """Delegates input request to GUI handler or returns default."""
    if gui_input_handler:
        result = gui_input_handler.request(prompt, valid_responses, default)
        if result is not None:
            return result
    return default if default else ""


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


# ==============================================================================
# CORE CLASSES
# ==============================================================================


class CommandExecutor:
    """Handles shell command execution with dry-run support and error handling."""

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

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
        if sudo:
            if not check_command_exists("sudo"):
                logger.error("Sudo command not found, cannot execute privileged task.")
                return False

            # Use non-interactive mode if no terminal is attached to prevent hanging
            if not sys.stdin or not sys.stdin.isatty():
                full_command = ["sudo", "-n"] + command
            else:
                full_command = ["sudo"] + command
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
            subprocess.run(full_command, shell=shell, check=True, timeout=timeout)
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
        log_step("Cleaning orphaned packages")

        if self.package_manager == "apt":
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
                        "Remove the orphaned packages? [y/N] ",
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
        log_step("Cleaning package cache")

        if self.package_manager == "apt":
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
                        "Clean package cache? [y/N] ", ["y", "n", ""], default="n"
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

        return list(set(config_files))[:30]  # Limit to 30 files for safety

    def clean_old_configurations(self) -> None:
        """Cleans old configuration files with user confirmation."""
        log_step("Cleaning old configuration files")

        config_files = self.find_old_configuration_files()

        if not config_files:
            logger.info("No old configuration files found")
            return

        logger.info(f"Old configuration files found ({len(config_files)}):")
        for file_path in config_files:
            logger.info(f"  {file_path}")

        logger.warning(
            "IMPORTANT: Some .pacnew and .pacsave files may contain important updates."
        )
        logger.warning("Review carefully before removing.")

        if self.executor.dry_run:
            logger.info("[DRY-RUN] Would prompt to remove old configuration files")
            return

        response = safe_input(
            "Remove ANY old configuration files? [y/N] ", ["y", "n", ""], default="n"
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
                    self.executor.execute(["rm", "-v", str(file_path)], sudo=True)
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
        self._deep_scan_cache: Optional[List[str]] = None
        self._flatpak_packages_cache: Optional[List[str]] = None
        self._snap_packages_cache: Optional[List[str]] = None

    def get_installed_packages(self) -> List[str]:
        """Retrieves list of currently installed packages.

        Returns:
            List of installed package names
        """
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
                return []

            return result.stdout.strip().split("\n")

        except Exception as error:
            logger.error(f"Error retrieving installed packages: {error}")
            return []

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

    def _get_deep_scan_files(self) -> List[str]:
        """Scans home directory for potential application files."""
        if self._deep_scan_cache is not None:
            return self._deep_scan_cache

        logger.info("Performing deep scan of home directory for applications...")
        files_found = []
        home = Path.home()
        exclude_dirs = {".cache", ".config", ".local", ".git", "__pycache__"}

        for root, dirs, files in os.walk(home):
            dirs[:] = [
                d for d in dirs if d not in exclude_dirs and not d.startswith(".")
            ]
            for file in files:
                files_found.append(file.lower())

        self._deep_scan_cache = files_found
        return files_found

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

        installed_packages = self.get_installed_packages()
        flatpak_packages = self.get_flatpak_packages() if self.deep_scan else []
        snap_packages = self.get_snap_packages() if self.deep_scan else []
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
                for item in root_directory.iterdir():
                    if (
                        not item.is_dir()
                        or item.name.lower() in skip_directories
                        or len(item.name) <= 2
                    ):
                        continue

                    # Check if item matches any installed package
                    is_found = any(
                        pkg in item.name or item.name in pkg
                        for pkg in installed_packages
                        if pkg
                    )

                    # Check if command exists in PATH
                    if not is_found:
                        if check_command_exists(item.name) or check_command_exists(
                            item.name.lower()
                        ):
                            is_found = True

                    # Deep Scan (Slow, Optional)
                    if not is_found and self.deep_scan:
                        # Check against Flatpak packages
                        if flatpak_packages and any(
                            pkg in item.name.lower() for pkg in flatpak_packages
                        ):
                            is_found = True

                        # Check against Snap packages
                        if (
                            not is_found
                            and snap_packages
                            and any(pkg in item.name.lower() for pkg in snap_packages)
                        ):
                            is_found = True

                        # Check for AppImages/binaries in home directory
                        if not is_found:
                            deep_files = self._get_deep_scan_files()
                            if any(item.name.lower() in f for f in deep_files):
                                is_found = True

                    if not is_found:
                        try:
                            size_bytes = sum(
                                f.stat().st_size for f in item.rglob("*") if f.is_file()
                            )
                        except Exception:
                            size_bytes = 0
                        orphaned_configs.append((item, size_bytes))

            except Exception as error:
                logger.warning(f"Could not scan {root_directory}: {error}")

        return orphaned_configs

    def clean_orphaned_configurations(self) -> None:
        """Identifies and optionally removes orphaned application configurations."""
        log_step("Cleaning orphaned application configurations")

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
            "Remove any of these configurations? [y/N] ", ["y", "n", ""], default="n"
        )
        if response != "y":
            logger.info("Keeping all orphaned configurations")
            return

        for path, _ in orphaned_configs:
            if path.exists():
                response = safe_input(
                    f"Remove {path}? [y/N] ", ["y", "n", ""], default="n"
                )
                if response == "y":
                    try:
                        self.executor.execute(["rm", "-rf", str(path)], sudo=False)
                        logger.info(f"Removed {path}")
                    except Exception as error:
                        logger.error(f"Failed to remove {path}: {error}")
                else:
                    logger.info(f"Kept {path}")


class SystemCacheCleaner:
    """Handles cleanup of system caches and user wastebasket."""

    def __init__(self, executor: CommandExecutor) -> None:
        self.executor = executor
        self.current_user = getpass.getuser()

    def clean_system_cache(self) -> None:
        """Cleans system temporary files in /tmp older than 7 days."""
        log_step("Cleaning system temporary files")

        if self.executor.dry_run:
            logger.info("[DRY-RUN] Would clean /tmp files older than 7 days")
            return

        response = safe_input(
            "Clean system temporary files in /tmp? [y/N] ",
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
        log_step(f"Cleaning wastebasket for user '{self.current_user}'")

        if self.executor.dry_run:
            logger.info(
                f"[DRY-RUN] Would clean wastebasket for user {self.current_user}"
            )
            return

        response = safe_input(
            f"Clean wastebasket (empty trash) for user {self.current_user}? [y/N] ",
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

        self.show_disk_usage()
        logger.info("System cleanup completed")

        if self.dry_run:
            logger.info("This was a dry-run. No changes were made.")


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
        title: str, message: str, buttons: List[tuple], icon: Optional[str] = None
    ) -> Any:
        dialog = tk.Toplevel()
        root = dialog.master
        dialog.title(title)
        if root:
            dialog.transient(cast(tk.Wm, root))
        dialog.grab_set()
        dialog.resizable(False, False)

        # Use a consistent font
        font_family = "Segoe UI" if os.name == "nt" else "Helvetica"
        font_size = 9 if os.name == "nt" else 10
        font_style = (font_family, font_size)

        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        if icon:
            # Attempt to match the dialog background color
            bg_color = ttk.Style().lookup("TFrame", "background")
            if not bg_color:
                bg_color = "#f0f0f0"

            icon_canvas = tk.Canvas(
                content_frame,
                width=56,
                height=56,
                highlightthickness=0,
                bg=bg_color,
            )
            icon_canvas.pack(side=tk.LEFT, anchor=tk.N, padx=(0, 15))

            GMessageBox._draw_icon(icon_canvas, icon)

        label = ttk.Label(
            content_frame,
            text=message,
            font=font_style,
            wraplength=350,
            justify=tk.LEFT,
        )
        label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        container = ttk.Frame(btn_frame)
        container.pack(anchor=tk.CENTER)

        result = None

        def on_btn(value):
            nonlocal result
            result = value
            dialog.destroy()

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

        dialog.bind("<Escape>", lambda e: dialog.destroy())

        # Center dialog
        dialog.update_idletasks()
        w = dialog.winfo_reqwidth()
        h = dialog.winfo_reqheight()

        if root:
            rx = root.winfo_x()
            ry = root.winfo_y()
            rw = root.winfo_width()
            rh = root.winfo_height()

            x = rx + (rw - w) // 2
            y = ry + (rh - h) // 2
            dialog.geometry(f"+{x}+{y}")

        dialog.wait_window()
        return result

    @staticmethod
    def showinfo(title: str, message: str) -> None:
        GMessageBox._create_dialog(
            title, message, [("OK", None, True)], icon="information"
        )

    @staticmethod
    def showwarning(title: str, message: str) -> None:
        GMessageBox._create_dialog(title, message, [("OK", None, True)], icon="warning")

    @staticmethod
    def showerror(title: str, message: str) -> None:
        GMessageBox._create_dialog(title, message, [("OK", None, True)], icon="error")

    @staticmethod
    def askyesno(title: str, message: str) -> Optional[bool]:
        return GMessageBox._create_dialog(
            title,
            message,
            [("Yes", True, True), ("No", False, False)],
            icon="question",
        )


class GuiInputHandler:
    """Handles user input requests via GUI dialogs in thread-safe manner."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.result = None
        self.event = threading.Event()

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
        self.event.wait()
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
                answer = GMessageBox.askyesno("Input Required", prompt)
                self.result = "y" if answer else "n"
        except Exception as error:
            logger.error(f"Error displaying dialog: {error}")
            self.result = default
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
        self.root.geometry("800x600")

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

        # Setup input handler
        global gui_input_handler
        gui_input_handler = GuiInputHandler(self.root)

        # Initialize UI
        self.setup_user_interface()

        # Start log polling
        self.root.after(100, self.process_log_queue)

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
            command=self.root.quit,
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
            GMessageBox.showwarning(
                "Real Mode Activated",
                "You have disabled Dry Run mode.\n\n"
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
