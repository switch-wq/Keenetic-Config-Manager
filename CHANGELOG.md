# Changelog

## v2.1.0-test1 — 2026-09-29

### Added
- Native WireGuard config import via `interface WireguardN wireguard import {url}` on KeeneticOS 5.2+.
- One-shot local HTTP delivery of the original `.conf` to the Keenetic native importer.
- AmneziaWG 3.0 / 3.1 parsing and ASC read-back.
- Support for HeaderProtectionKey and the new AWG 3.x timing/padding options.

### Changed
- Rollback baseline is no longer mandatory and no longer blocks config updates.
- Main update action simplified to `Обновить конфиг`.
- Native import is preferred; legacy per-field update remains a fallback path.
- Safety backups remain automatic before configuration changes.

### Fixed
- AWG 3.1 → AWG 2.0 replacement on KeeneticOS 5.2 Alpha 11 when the same config succeeds through the Keenetic web UI.
- Handshake sentinel values (`0`, negative, `>= Int32.MaxValue`) are no longer reported as successful handshakes.

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
