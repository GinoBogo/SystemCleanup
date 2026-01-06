# System Cleanup Utility

A robust, GUI-based system cleanup tool designed for Arch Linux and Ubuntu/Debian based systems. This utility helps maintain system hygiene by removing orphaned packages, clearing caches, and identifying leftover configuration files.

## Features

- **User-Friendly GUI**: Built with Tkinter for easy interaction.
- **Dry-Run Mode**: Simulates cleanup operations without making changes (enabled by default) to ensure safety.
- **Deep Scan Mode**: Optional thorough scan to identify applications installed outside package managers (AppImages, binaries, Flatpaks, Snaps) to prevent false positives when cleaning configurations.
- **Task Selection**: Toggle specific cleanup tasks:
  - **Orphaned Packages**: Removes unused dependencies.
  - **Package Cache**: Clears downloaded package archives.
  - **Old Configurations**: Finds and removes backup config files (e.g., `.pacnew`, `.dpkg-old`).
  - **App Configurations**: Identifies orphaned folders in `~/.config` and `~/.local`.
  - **System Cache**: Cleans temporary files in `/tmp` older than 7 days.
  - **Wastebasket**: Empties the user's trash.
- **Safety First**: Includes confirmation dialogs and detailed logging before destructive actions.

## Requirements

- **Operating System**: Linux (Arch Linux or Ubuntu/Debian derivatives recommended).
- **Python**: Version 3.6 or higher.
- **Tkinter**: Python's standard GUI interface.
  - *Ubuntu/Debian*: `sudo apt install python3-tk`
  - *Arch Linux*: `sudo pacman -S tk`
- **Permissions**: `sudo` privileges are required for system-level cleanup tasks (e.g., package removal).

## Installation

1. Clone the repository or download the script.
2. Ensure the script is executable:
   ```bash
   chmod +x system_cleanup.py
   ```

## Usage

Run the script from the terminal:

```bash
./system_cleanup.py
```
or
```bash
python3 system-cleanup.py
```

### Operation

1. **Select Options**:
   - **Dry Run**: Keep checked to see what *would* happen without deleting anything. Uncheck to perform actual cleanup.
   - **Deep Scan**: Check this if you use AppImages or manual binary installations to ensure their config files aren't flagged as orphaned.
2. **Select Tasks**: Check the boxes for the cleanup operations you wish to perform.
3. **Start**: Click the "Start" button.
4. **Review**: Watch the log output. If running in real mode, answer the confirmation dialogs that appear.

## Disclaimer

This software deletes files. While it includes safety mechanisms like Dry-Run mode and confirmation prompts, **always review the log output carefully** before confirming deletions. The author is not responsible for any data loss.

## Author

Gino Bogo

## License

MIT License
