# Persistence scripts (Linux and Windows)

These scripts provide repeatable examples of setting up persistence mechanisms for **authorized** system administration, lab testing, or defensive validation. They are written to be explicit about what they change and how to remove those changes.

## Linux

- `linux/systemd_service.sh`: creates and enables a systemd service (user or system scope) for a given executable.
- `linux/cron_reboot.sh`: adds a cron entry (default: `@reboot`) for the current user without duplicating existing entries.
- `linux/xdg_autostart.sh`: writes an XDG-compliant desktop autostart entry for graphical sessions.

### General usage

All Linux scripts are POSIX shell scripts. Make them executable with `chmod +x <script>` if necessary.

## Windows

- `windows/create_scheduled_task.ps1`: registers a scheduled task that runs at logon by default.
- `windows/add_run_key.ps1`: adds a value to the `Run` registry key for the current user or local machine.
- `windows/install_service.ps1`: installs a Windows service that runs a provided executable.

### General usage

Run PowerShell scripts from an elevated PowerShell session when system-level changes are required. Each script includes parameters to define the persistence behavior and cleanup instructions for removing the change.

---

Use these scripts only on systems you are authorized to manage. Review the generated files (systemd units, cron entries, registry keys, or scheduled tasks) before enabling them in production.
