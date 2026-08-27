# Changelog

## v2.0.0 — 2026-08-27

### Added
- Portable single-EXE launcher.
- Safe updater for WireGuard / AmneziaWG / AmneziaWG 2.0.
- DPAPI rollback baseline.
- Full startup/running/routes safety backups.
- Automatic rollback on failed update.
- Static routes manager.
- BAT/CMD/TXT and IP/CIDR bulk route import.
- Duplicate Skip for existing/repeated ADD routes.
- Route batching up to 950 changes per batch.
- Async route loading with loading overlay.
- Background interface/handshake/routes status worker.
- Configurable Keenetic router URL and credentials.
- Dark WPF UI and custom scrollbars.
- Single-instance protection.

### Changed
- Main application is distributed as one EXE instead of a visible PowerShell/VBS launcher set.
- Route loading and status polling moved away from the UI thread to reduce freezes.
- Secondary tools moved into a collapsible “Дополнительные инструменты” section.
- Route manager and dialogs were moved to the same dark WPF visual style.

### Safety
- Old peer is not removed until the new configuration passes validation.
- PrivateKey rollback data is stored locally using Windows DPAPI.
- Route changes create a full backup before modification and support automatic rollback on failure.
