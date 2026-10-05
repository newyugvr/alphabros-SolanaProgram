# Alphabros Router (Solana)

A fee router for swaps on Solana. Anyone creates a router with a trader fee that is fixed forever; users swap through
it with the venue they choose and pay an exact fee in SOL.

**Program (mainnet-beta):** `9Gv5FLbNg4iKEDK9dM7twBrCjc65KEMpthG3SoYq53Aa`

## How it works

- **Fee** = max(floor, SOL side × (0.25% protocol + 0–0.25% trader)), measured on what actually moved in the user's
  token accounts, charged in SOL after the swap, never above the `max_fee` the user signed. Fees are credited inside
  the program and each wallet collects its own credit with `collect` (anyone may trigger it; the SOL only ever goes to
  that wallet).
- **Every swap has wSOL on one side** (`UnpricedPair` otherwise), spends something from the measured input
  (`ZeroInput`) and never more than the signed `max_input` (`InputTooHigh`), and returns at least `min_out`.
- **Venues are permissionless.** The user signs the transaction and so chooses the venue (Jupiter v6, another
  aggregator, a DEX). What makes any venue safe to call is what `execute` enforces around it:
  - the only writable token accounts of the user's (owned or delegated) the swap may receive are the measured input
    and output (`SwapAccountNotBound`); no SPL multisig may appear (`MultisigNotAllowed`);
  - no account a native program owns (stake, vote, program data, lookup table) may be writable in the swap, nor a
    system account holding data such as a durable nonce (`ProtectedAccount`);
  - only the user's signature is passed on, and the user's wallet reaches the swap read-only (see `execute_v2`);
  - the owner, delegate and close authority of both measured accounts must be unchanged after the swap
    (`AccountAuthorityChanged`), and neither may lose lamports beyond its token amount: rent, surplus or unsynced
    wSOL lamports (`AccountLamportsTaken`);
  - the router itself and the native programs are never venues (`VenueNotAllowed`).
- **`execute_v2`** is `execute` for venues that trade the wallet's own SOL (bonding curves such as Pump.fun, AMMs
  that take SOL fees or rent from the wallet). The user signs `max_wallet_spend` (at most 100 SOL); above zero, the
  wallet is writable in the swap. After the swap the wallet must still be a plain system account (`WalletTampered`)
  that lost at most `max_wallet_spend` (`WalletSpendTooHigh`). The SOL side is measured net, the wSOL account's change
  plus the wallet's change, signed, and `max_input`, `min_out` and the fee apply to that. `execute` is unchanged.
- **Jupiter v6:** the instruction must be one of its ten route instructions (`JupiterNotARoute`) with Jupiter's own
  platform fee off: no platform-fee account on the six original routes, `platform_fee_bps` and
  `positive_slippage_bps` zero on the four v2 routes (`JupiterPlatformFee`).

## Who can change what

| Setting | Who | Notes |
| --- | --- | --- |
| Fee rates (0.25% protocol, trader ≤ 0.25%) | nobody | constants in the program |
| A router's trader fee | nobody | fixed when the router is created |
| Floor cap | nobody | fixed at `initialize` |
| Floor | config owner | never above the cap |
| Protocol fee wallet | config owner | credits already earned stay with the old wallet |
| A router's fee wallet | that router's owner | same |
| Config / router ownership | current owner | two steps: `transfer_*_ownership`, then `accept_*_ownership` |

Nobody can move a user's tokens except through that user's own `execute` or `execute_v2`, or move anyone's credit.

## Layout

| Path | What |
| --- | --- |
| `programs/alphabros_router` | The program (Anchor 1.2.0): the only thing deployed |
| `programs/mock_swap` | Test-only swap venue; `relay` is a hostile venue that does whatever a test asks with the user's signature |
| `tests/tests/router.rs` | LiteSVM tests against the compiled programs |
| `tests/tests/jupiter_fork.rs` | Real Jupiter routes on real mainnet state (snapshots from `live/jupiter-snapshot.mjs`; skipped without them) |
| `.github/workflows/verifiable-build.yml` | Reproducible build with `solana-verify`, tests against that binary, IDL |

## Build, test, verify

```sh
# Reproducible build (Docker; image pinned in Cargo.toml [workspace.metadata.cli]):
solana-verify build --library-name alphabros_router
solana-verify get-executable-hash target/deploy/alphabros_router.so

# Compare with the deployed program:
solana-verify get-program-hash -u mainnet-beta 9Gv5FLbNg4iKEDK9dM7twBrCjc65KEMpthG3SoYq53Aa

# Tests (LiteSVM; stable Rust >= 1.97.1), after building both programs into target/deploy:
cd tests && cargo test --test router

# Optional mainnet-fork tests: snapshot real Jupiter routes (needs SOLANA_MAINNET_RPC_URL in a local .env), then
cd live && npm install && node jupiter-snapshot.mjs && cd ../tests && cargo test --test jupiter_fork
```

## License

MIT
