# kite-mcp-users

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-users.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-users)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

User identity store for the algo2go ecosystem. Provides user CRUD,
role-based access control (admin/trader/viewer), bcrypt-hashed
password storage, TOTP-based MFA enrollment (admin-only), and
invitation tokens. SQLite-backed via the algo2go/kite-mcp-alerts
shared DB.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for admin login, role gating, MFA enrollment, and invitation flows.

## Why a separate module?

User identity + RBAC + MFA are foundational primitives for any
algo2go consumer that needs admin/trader/viewer separation. Hosting
as a module:

- Centralizes the user store + RBAC contract across consumers
- Lets MFA + bcrypt + TOTP signatures version independently
- Pairs cleanly with `algo2go/kite-mcp-alerts` (shared DB) and
  upstream consumers needing admin gating

## Stability promise

**v0.x — unstable.** Type signatures may evolve as RBAC + MFA
patterns mature. Pin `v0.1.0` deliberately. v1.0 ships only after
the public API (Store, Role/Status constants, MFA enrollment, TOTP
helpers, invitation tokens) is reviewed for stability.

## Install

```bash
go get github.com/algo2go/kite-mcp-users@v0.1.0
```

## Public API (selected)

### Store
- `Store` — user CRUD with `*alerts.DB` backend
- `NewStore(db *alerts.DB) *Store` — constructor
- `Store.Create / Read / Update / Delete / List` — RBAC-aware CRUD

### Role + status constants
- `RoleAdmin`, `RoleTrader`, `RoleViewer`
- `StatusActive`, `StatusSuspended`, `StatusOffboarded`

### MFA (admin-only)
- `Store.SetEncryptionKey(key []byte)` — wires AES-256 key for TOTP
  secret encryption at rest
- `Store.EnrollMFA / VerifyMFA / DisableMFA` — admin TOTP lifecycle
- `ProvisioningURI(secret, issuer, account) string` — RFC 6238 URI
- `VerifyTOTP(secret, code) bool` — TOTP code verification

### Invitations
- `Store.CreateInvitation / RedeemInvitation` — token-based onboarding

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` — shared DB backend
- `github.com/stretchr/testify` — assertions
- `golang.org/x/crypto/bcrypt` — password hashing

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by:
- `app/wire.go`, `app/app.go` — service wiring + admin route gating
- `oauth/handlers_admin_mfa.go` — admin MFA enrollment flow
- `kc/manager_init.go`, `kc/store_registry.go` — service registry
- `kc/usecases/admin_usecases.go`, `family_usecases.go` — use cases
- `kc/ops/admin/render.go` — admin dashboard rendering
- `mcp/admin_tools_test.go` — admin MCP tool tests
- `plugins/rolegate/plugin.go` — RBAC viewer-blocks-write plugin
- `plugins/telegramnotify/plugin.go` — family-admin DM after-hook

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
