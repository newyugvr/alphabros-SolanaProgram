//! Alphabros V2 fee router for Solana.
//!
//! Anyone creates a router (a small config account) with a trader fee fixed forever. Users swap through a router:
//! the program runs the swap by CPI into the swap program the user signed for (any venue: Jupiter v6, another
//! aggregator, a DEX) with the user's own token accounts and signature, measures what actually moved on the user's
//! accounts, and charges an exact fee in SOL:
//!
//!     fee = max(min_fee, ceil(SOL side x (25 + trader_fee_bps) / 10_000))
//!
//! never above the `max_fee` the user signed. Every swap must have wSOL on one side, so the fee is always priced
//! on-chain. The fee is credited in the program (protocol 25 / total, the router's fee wallet the rest) and each
//! wallet collects its own credit later; nothing is pushed during a swap. This router's only SOL debit from the user
//! is that fee, capped by `max_fee`: credit accounts are created (and paid for) when a wallet is set, never during a
//! swap. Network fees and the user's own wrap/unwrap instructions are outside the program.
//!
//! Venues are permissionless: there is no allowlist to govern. The user signs the transaction and so chooses the venue;
//! what makes any venue safe to call is what `execute` enforces around it (the swap is bound to the measured accounts,
//! only the user's signature is passed on, the user's SOL wallet and native-program accounts are out of reach, no
//! approval or authority change survives, spent <= max_input, received >= min_out). A short block list refuses
//! programs that are never venues (this program itself and the native programs). When the venue is Jupiter v6, its own
//! platform fee must be off, so no fee is taken beside this router's.
//!
//! Who can change what: the config owner sets the floor (never above `max_min_fee`, fixed at initialize) and the
//! protocol wallet. A router's owner sets its fee wallet. Nobody can change the fee rates, the cap, a router's trader
//! fee, or move a user's tokens or anyone's credit.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    system_instruction,
};
use anchor_spl::token_interface::TokenAccount;

// Security contact and source, readable by explorers (solana-security-txt). Not part of the library build.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "Alphabros Router",
    project_url: "https://github.com/newyugvr/alphabros-SolanaProgram",
    contacts: "link:https://github.com/newyugvr/alphabros-SolanaProgram/security",
    policy: "https://github.com/newyugvr/alphabros-SolanaProgram/security",
    source_code: "https://github.com/newyugvr/alphabros-SolanaProgram"
}

declare_id!("9Gv5FLbNg4iKEDK9dM7twBrCjc65KEMpthG3SoYq53Aa");

/// Protocol fee: 0.25% of the trade. Fixed forever.
pub const PROTOCOL_FEE_BPS: u64 = 25;
/// Most a trader can add: 0.25% of the trade (0.5% total). Fixed forever.
pub const MAX_TRADER_FEE_BPS: u16 = 25;
pub const BPS: u64 = 10_000;
/// Most wallet SOL an `execute_v2` swap may be signed to spend: 100 SOL.
pub const MAX_WALLET_SPEND: u64 = 100_000_000_000;
/// Jupiter v6: the one venue whose instruction is checked (its own platform fee must be off).
pub const JUPITER_V6: Pubkey = pubkey!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
/// Native programs. None is ever a venue, and the swap may never be handed a WRITABLE account any of them owns
/// (stake, vote, program-data, lookup-table and config accounts can name the user as their authority). The System
/// program is first.
pub const NATIVE_PROGRAMS: [Pubkey; 9] = [
    pubkey!("11111111111111111111111111111111"),
    pubkey!("Stake11111111111111111111111111111111111111"),
    pubkey!("Vote111111111111111111111111111111111111111"),
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111"),
    pubkey!("BPFLoader2111111111111111111111111111111111"),
    pubkey!("BPFLoader1111111111111111111111111111111111"),
    pubkey!("LoaderV411111111111111111111111111111111111"),
    pubkey!("AddressLookupTab1e1111111111111111111111111"),
    pubkey!("Config1111111111111111111111111111111111111"),
];
/// Wrapped SOL: the only mint the program can value itself (1 token unit = 1 lamport).
pub const WSOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");

pub const CONFIG_SEED: &[u8] = b"config";
pub const VAULT_SEED: &[u8] = b"vault";
pub const ROUTER_SEED: &[u8] = b"router";
pub const CREDIT_SEED: &[u8] = b"credit";

#[program]
pub mod alphabros_router {
    use super::*;

    /// One-time setup, by the program's upgrade authority only (so nobody can front-run it after deploy). Creates the
    /// protocol wallet's credit account here, paid by the deployer, so no swap ever pays for it.
    pub fn initialize(
        ctx: Context<Initialize>,
        owner: Pubkey,
        protocol_wallet: Pubkey,
        min_fee: u64,
        max_min_fee: u64,
    ) -> Result<()> {
        require_keys_neq!(owner, Pubkey::default(), RouterError::ZeroAddress);
        check_wallet(&protocol_wallet, &ctx.accounts.vault.key())?;
        require!(min_fee <= max_min_fee, RouterError::AboveCap);

        let config = &mut ctx.accounts.config;
        config.owner = owner;
        config.pending_owner = Pubkey::default();
        config.protocol_wallet = protocol_wallet;
        config.min_fee = min_fee;
        config.max_min_fee = max_min_fee;
        config.total_credited = 0;
        config.bump = ctx.bumps.config;
        config.vault_bump = ctx.bumps.vault;

        // The vault holds credited fees as lamports. Fund it to rent exemption once, so paying out a credit can never
        // take it below the rent minimum; `total_credited` never counts this reserve.
        let rent_min = Rent::get()?.minimum_balance(0);
        let have = ctx.accounts.vault.lamports();
        if have < rent_min {
            invoke(
                &system_instruction::transfer(&ctx.accounts.payer.key(), &ctx.accounts.vault.key(), rent_min - have),
                &[
                    ctx.accounts.payer.to_account_info(),
                    ctx.accounts.vault.to_account_info(),
                    ctx.accounts.system_program.to_account_info(),
                ],
            )?;
        }
        ensure_credit(&ctx.accounts.protocol_credit, protocol_wallet, &ctx.accounts.payer, &ctx.accounts.system_program)?;

        emit!(Initialized { owner, protocol_wallet, min_fee, max_min_fee });
        Ok(())
    }

    /// Anyone creates a router. The signer owns it; `fee_wallet` receives the trader's share; the trader fee is fixed
    /// forever (another rate = another router, with another salt). The fee wallet's credit account is created here,
    /// paid by the router owner, so no swap ever pays for it.
    pub fn create_router(
        ctx: Context<CreateRouter>,
        fee_wallet: Pubkey,
        trader_fee_bps: u16,
        salt: [u8; 32],
    ) -> Result<()> {
        require!(trader_fee_bps <= MAX_TRADER_FEE_BPS, RouterError::AboveCap);
        check_wallet(&fee_wallet, &ctx.accounts.vault.key())?;
        ensure_credit(&ctx.accounts.fee_credit, fee_wallet, &ctx.accounts.owner, &ctx.accounts.system_program)?;
        let router = &mut ctx.accounts.router;
        router.owner = ctx.accounts.owner.key();
        router.pending_owner = Pubkey::default();
        router.fee_wallet = fee_wallet;
        router.trader_fee_bps = trader_fee_bps;
        router.salt = salt;
        router.bump = ctx.bumps.router;
        emit!(RouterCreated { router: router.key(), owner: router.owner, fee_wallet, trader_fee_bps, salt });
        Ok(())
    }

    /// Router owner: where future trader shares go (its credit account is created now, paid by the owner). Credits
    /// already earned stay with the old wallet.
    pub fn set_fee_wallet(ctx: Context<SetFeeWallet>, wallet: Pubkey) -> Result<()> {
        check_wallet(&wallet, &ctx.accounts.vault.key())?;
        ensure_credit(&ctx.accounts.credit, wallet, &ctx.accounts.owner, &ctx.accounts.system_program)?;
        ctx.accounts.router.fee_wallet = wallet;
        emit!(FeeWalletSet { router: ctx.accounts.router.key(), wallet });
        Ok(())
    }

    pub fn transfer_router_ownership(ctx: Context<RouterOwnerOnly>, new_owner: Pubkey) -> Result<()> {
        ctx.accounts.router.pending_owner = new_owner;
        Ok(())
    }

    pub fn accept_router_ownership(ctx: Context<AcceptRouterOwnership>) -> Result<()> {
        let router = &mut ctx.accounts.router;
        router.owner = ctx.accounts.new_owner.key();
        router.pending_owner = Pubkey::default();
        Ok(())
    }

    /// Config owner: the floor, in lamports, never above the cap fixed at initialize.
    pub fn set_min_fee(ctx: Context<ConfigOwnerOnly>, lamports: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(lamports <= config.max_min_fee, RouterError::AboveCap);
        config.min_fee = lamports;
        emit!(MinFeeSet { lamports });
        Ok(())
    }

    /// Config owner: where future protocol shares go (its credit account is created now, paid by the owner). Credits
    /// already earned stay with the old wallet.
    pub fn set_protocol_wallet(ctx: Context<SetProtocolWallet>, wallet: Pubkey) -> Result<()> {
        check_wallet(&wallet, &ctx.accounts.vault.key())?;
        ensure_credit(&ctx.accounts.credit, wallet, &ctx.accounts.owner, &ctx.accounts.system_program)?;
        ctx.accounts.config.protocol_wallet = wallet;
        emit!(ProtocolWalletSet { wallet });
        Ok(())
    }

    pub fn transfer_config_ownership(ctx: Context<ConfigOwnerOnly>, new_owner: Pubkey) -> Result<()> {
        ctx.accounts.config.pending_owner = new_owner;
        Ok(())
    }

    pub fn accept_config_ownership(ctx: Context<AcceptConfigOwnership>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.owner = ctx.accounts.new_owner.key();
        config.pending_owner = Pubkey::default();
        Ok(())
    }

    /// Swap through `router`, paying at most `max_fee` lamports and spending at most `max_input` of the input token.
    ///
    /// The swap is `swap_data` sent to `swap_program` (any venue the user signed for, except the blocked ones) with
    /// `remaining_accounts`, carrying the user's signature. The venue may pass that signature on to the programs it
    /// calls, so the router BINDS the swap to the measured accounts: among the accounts handed to the swap, the only
    /// writable token accounts the user owns (or is a delegate of) may be `input_account` and `output_account`, no SPL
    /// multisig may appear, no account a native program owns may be writable (nor a system account holding data, such
    /// as a durable nonce), only the user's signature is passed on, and the user's wallet is read-only. The swap
    /// therefore has nothing of the user's to spend except `input_account`, and it must leave the owner, delegate and
    /// close authority of both measured accounts unchanged. For Jupiter v6 the instruction must be a route with its
    /// platform fee off.
    ///
    /// After the swap: spent > 0, spent <= max_input, received >= min_out, and the fee is exactly
    /// max(min_fee, ceil(wSOL side x total bps / 10_000)) from the user's SOL, reverting if above `max_fee`. That fee is
    /// this router's only SOL debit from the user (no account is created during a swap); network fees and the app's
    /// wrap/unwrap instructions are outside it. For a SOL trade the app wraps SOL into the user's wSOL account before
    /// this instruction (and may unwrap after).
    pub fn execute<'info>(
        ctx: Context<'info, Execute<'info>>,
        min_out: u64,
        max_fee: u64,
        max_input: u64,
        deadline: i64,
        swap_data: Vec<u8>,
    ) -> Result<()> {
        execute_swap(ctx, min_out, max_fee, max_input, 0, deadline, swap_data)
    }

    /// `execute` for venues that trade the wallet's own SOL (bonding curves such as Pump.fun, and AMMs that take a
    /// SOL fee or rent from the wallet). The wallet is writable in the swap when `max_wallet_spend` is above zero, and
    /// the swap may take at most `max_wallet_spend` lamports from it (never above `MAX_WALLET_SPEND`). After the swap
    /// the wallet must still be a plain system account (System-owned, no data): an Assign or Allocate of the wallet
    /// reverts. Every other rule of `execute` holds.
    ///
    /// The wallet's SOL counts on the SOL side, NET: the SOL side is the signed sum of the wSOL account's change and
    /// the wallet's change, so on a buy `spent` is the net SOL that left both, and on a sell `received` is the net SOL
    /// that arrived in both (a loss on either side is subtracted, never ignored). `max_input`, `min_out` and the fee
    /// apply to those net amounts. The router's own fee is taken after this measurement.
    pub fn execute_v2<'info>(
        ctx: Context<'info, Execute<'info>>,
        min_out: u64,
        max_fee: u64,
        max_input: u64,
        max_wallet_spend: u64,
        deadline: i64,
        swap_data: Vec<u8>,
    ) -> Result<()> {
        require!(max_wallet_spend <= MAX_WALLET_SPEND, RouterError::AboveCap);
        execute_swap(ctx, min_out, max_fee, max_input, max_wallet_spend, deadline, swap_data)
    }

    /// Pays `wallet` everything credited to it. Anyone may trigger it; the lamports only ever go to `wallet`.
    pub fn collect(ctx: Context<Collect>) -> Result<()> {
        let amount = ctx.accounts.credit.amount;
        if amount == 0 {
            return Ok(());
        }
        ctx.accounts.credit.amount = 0;
        let config = &mut ctx.accounts.config;
        config.total_credited = config.total_credited.checked_sub(amount).ok_or(RouterError::MathOverflow)?;
        let vault_bump = config.vault_bump;
        invoke_signed(
            &system_instruction::transfer(&ctx.accounts.vault.key(), &ctx.accounts.wallet.key(), amount),
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.wallet.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
            &[&[VAULT_SEED, &[vault_bump]]],
        )?;
        emit!(Collected { wallet: ctx.accounts.wallet.key(), amount });
        Ok(())
    }
}

// ============================================================================ helpers

/// The swap behind `execute` (`max_wallet_spend` = 0: the wallet is read-only) and `execute_v2`.
fn execute_swap<'info>(
    ctx: Context<'info, Execute<'info>>,
    min_out: u64,
    max_fee: u64,
    max_input: u64,
    max_wallet_spend: u64,
    deadline: i64,
    swap_data: Vec<u8>,
) -> Result<()> {
    require!(Clock::get()?.unix_timestamp <= deadline, RouterError::Expired);
    require!(min_out > 0, RouterError::ZeroMinOut);

    let in_mint = ctx.accounts.input_account.mint;
    let out_mint = ctx.accounts.output_account.mint;
    require_keys_neq!(in_mint, out_mint, RouterError::SameToken);
    require!(in_mint == WSOL_MINT || out_mint == WSOL_MINT, RouterError::UnpricedPair);

    let swap_program = ctx.accounts.swap_program.key();
    check_venue(&swap_program, &swap_data, ctx.remaining_accounts)?;

    let user = ctx.accounts.user.key();
    let input_key = ctx.accounts.input_account.key();
    let output_key = ctx.accounts.output_account.key();
    check_swap_accounts(ctx.remaining_accounts, &user, &input_key, &output_key)?;

    let in_before = ctx.accounts.input_account.amount;
    let wallet_before = ctx.accounts.user.lamports();
    let out_before = ctx.accounts.output_account.amount;
    let in_auth = authorities(&ctx.accounts.input_account);
    let out_auth = authorities(&ctx.accounts.output_account);
    let in_excess = excess_lamports(&ctx.accounts.input_account);
    let out_excess = excess_lamports(&ctx.accounts.output_account);

    // The swap. Only the user's signature is passed on (any other signer in the transaction is dropped), and the
    // user's wallet is read-only unless the user signed a wallet spend (`execute_v2`): without one the swap can use
    // the user's signature, never move the wallet's SOL.
    let wallet_writable = max_wallet_spend > 0;
    let metas: Vec<AccountMeta> = ctx
        .remaining_accounts
        .iter()
        .map(|a| AccountMeta {
            pubkey: *a.key,
            is_signer: a.is_signer && *a.key == user,
            is_writable: a.is_writable && (*a.key != user || wallet_writable),
        })
        .collect();
    let mut infos: Vec<AccountInfo<'info>> = ctx.remaining_accounts.to_vec();
    infos.push(ctx.accounts.swap_program.to_account_info());
    invoke(&Instruction { program_id: swap_program, accounts: metas, data: swap_data }, &infos)?;

    ctx.accounts.input_account.reload()?;
    ctx.accounts.output_account.reload()?;
    // The swap held the user's signature: it may move tokens, but must leave both accounts' owner, delegate and
    // close authority exactly as they were (no approval or authority change can outlive the transaction).
    require!(authorities(&ctx.accounts.input_account) == in_auth, RouterError::AccountAuthorityChanged);
    require!(authorities(&ctx.accounts.output_account) == out_auth, RouterError::AccountAuthorityChanged);
    // Neither measured account may lose SOL that is not its token amount (rent, surplus lamports, unsynced lamports
    // of a wSOL account): a swap could otherwise withdraw them, or sync them into the measured amount.
    require!(excess_lamports(&ctx.accounts.input_account) >= in_excess, RouterError::AccountLamportsTaken);
    require!(excess_lamports(&ctx.accounts.output_account) >= out_excess, RouterError::AccountLamportsTaken);
    // The wallet: still a plain system account (no Assign, no Allocate), and at most `max_wallet_spend` lamports
    // gone.
    let wallet = ctx.accounts.user.to_account_info();
    require!(wallet.owner == &NATIVE_PROGRAMS[0] && wallet.data_is_empty(), RouterError::WalletTampered);
    let wallet_after = wallet.lamports();
    require!(wallet_before.saturating_sub(wallet_after) <= max_wallet_spend, RouterError::WalletSpendTooHigh);
    // The SOL side is measured NET: the wSOL account's change plus the wallet's change, signed, so a loss on one
    // can never hide behind a gain on the other. The token side is the measured account's own change.
    let wallet_change = wallet_after as i128 - wallet_before as i128;
    let (spent, received) = if in_mint == WSOL_MINT {
        let sol_change = ctx.accounts.input_account.amount as i128 - in_before as i128 + wallet_change;
        let spent = u64::try_from((-sol_change).max(0)).map_err(|_| error!(RouterError::MathOverflow))?;
        (spent, ctx.accounts.output_account.amount.saturating_sub(out_before))
    } else {
        let sol_change = ctx.accounts.output_account.amount as i128 - out_before as i128 + wallet_change;
        let received = u64::try_from(sol_change.max(0)).map_err(|_| error!(RouterError::MathOverflow))?;
        (in_before.saturating_sub(ctx.accounts.input_account.amount), received)
    };
    require!(spent > 0, RouterError::ZeroInput);
    require!(spent <= max_input, RouterError::InputTooHigh);
    require!(received >= min_out, RouterError::InsufficientOutput);

    // Exact fee on the wSOL side of what actually moved.
    let total_bps = PROTOCOL_FEE_BPS + ctx.accounts.router.trader_fee_bps as u64;
    let sol_side = core::cmp::max(
        if in_mint == WSOL_MINT { spent } else { 0 },
        if out_mint == WSOL_MINT { received } else { 0 },
    );
    let fee = core::cmp::max(ctx.accounts.config.min_fee, pct(sol_side, total_bps)?);
    require!(fee <= max_fee, RouterError::FeeTooLow);

    if fee > 0 {
        invoke(
            &system_instruction::transfer(&user, &ctx.accounts.vault.key(), fee),
            &[
                ctx.accounts.user.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
    }
    let protocol_fee = (fee as u128 * PROTOCOL_FEE_BPS as u128 / total_bps as u128) as u64;
    let trader_fee = fee - protocol_fee;
    let protocol_wallet = ctx.accounts.config.protocol_wallet;
    let fee_wallet = ctx.accounts.router.fee_wallet;
    add_credit(&ctx.accounts.protocol_credit, protocol_wallet, protocol_fee)?;
    add_credit(&ctx.accounts.trader_credit, fee_wallet, trader_fee)?;
    let config = &mut ctx.accounts.config;
    config.total_credited = config.total_credited.checked_add(fee).ok_or(RouterError::MathOverflow)?;

    emit!(Executed {
        user,
        router: ctx.accounts.router.key(),
        input_mint: in_mint,
        output_mint: out_mint,
        spent,
        received,
        fee,
        protocol_fee,
        trader_fee,
    });
    Ok(())
}

/// A token account's lamports that are not its token amount: everything for a non-native account, the rent and any
/// unsynced lamports for a wSOL account.
fn excess_lamports(a: &InterfaceAccount<TokenAccount>) -> u64 {
    let lamports = a.to_account_info().lamports();
    if a.mint == WSOL_MINT { lamports.saturating_sub(a.amount) } else { lamports }
}

/// `amount` x `bps` / 10,000, rounded up.
pub fn pct(amount: u64, bps: u64) -> Result<u64> {
    let v = (amount as u128 * bps as u128 + (BPS as u128 - 1)) / BPS as u128;
    u64::try_from(v).map_err(|_| error!(RouterError::MathOverflow))
}

/// Who controls a token account: owner, delegate (with its allowance) and close authority.
fn authorities(a: &TokenAccount) -> (Pubkey, Option<Pubkey>, u64, Option<Pubkey>) {
    (a.owner, a.delegate.into(), a.delegated_amount, a.close_authority.into())
}

/// Refuses programs that are never venues (this program, the native programs), and for Jupiter v6 requires a route
/// instruction with its platform fee off.
fn check_venue(program: &Pubkey, data: &[u8], accounts: &[AccountInfo]) -> Result<()> {
    require!(*program != crate::ID && !NATIVE_PROGRAMS.contains(program), RouterError::VenueNotAllowed);
    if *program == JUPITER_V6 {
        check_jupiter(data, accounts)?;
    }
    Ok(())
}

/// Jupiter v6 route instructions (Anchor discriminators) and where each keeps its platform fee (layouts from Jupiter's
/// on-chain IDL).
///
/// The six original routes take the fee into an optional `platform_fee_account` at a fixed position; it must be absent
/// (Anchor passes Jupiter's own program id for an absent optional account), so there is nowhere for a fee to go. Their
/// `platform_fee_bps` is the LAST argument, after a variable-length route plan, and Jupiter ignores trailing bytes, so
/// that byte cannot be trusted from the end of the data; the account check is what holds.
const JUPITER_V1_ROUTES: [([u8; 8], usize); 6] = [
    ([0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a], 6), // route
    ([0x96, 0x56, 0x47, 0x74, 0xa7, 0x5d, 0x0e, 0x68], 6), // route_with_token_ledger
    ([0xd0, 0x33, 0xef, 0x97, 0x7b, 0x2b, 0xed, 0x5c], 7), // exact_out_route
    ([0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81], 9), // shared_accounts_route
    ([0xe6, 0x79, 0x8f, 0x50, 0x77, 0x9f, 0x6a, 0xaa], 9), // shared_accounts_route_with_token_ledger
    ([0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e], 9), // shared_accounts_exact_out_route
];

/// The four v2 routes have no fee account; their fee is `platform_fee_bps: u16` and `positive_slippage_bps: u16` at a
/// fixed offset BEFORE the route plan ([id u8 for shared routes] amount u64, quoted u64, slippage u16, fee u16,
/// positive slippage u16), so both are read exactly and must be zero. The number is the leading `id` byte count.
const JUPITER_V2_ROUTES: [([u8; 8], usize); 4] = [
    ([0xbb, 0x64, 0xfa, 0xcc, 0x31, 0xc4, 0xaf, 0x14], 0), // route_v2
    ([0x9d, 0x8a, 0xb8, 0x52, 0x15, 0xf4, 0xf3, 0x24], 0), // exact_out_route_v2
    ([0xd1, 0x98, 0x53, 0x93, 0x7c, 0xfe, 0xd8, 0xe9], 1), // shared_accounts_route_v2
    ([0x35, 0x60, 0xe5, 0xca, 0xd8, 0xbb, 0xfa, 0x18], 1), // shared_accounts_exact_out_route_v2
];

/// Any Jupiter instruction other than these ten routes is refused.
fn check_jupiter(data: &[u8], accounts: &[AccountInfo]) -> Result<()> {
    let disc = data.get(..8).ok_or(error!(RouterError::JupiterNotARoute))?;
    if let Some((_, fee_index)) = JUPITER_V1_ROUTES.iter().find(|(d, _)| d == disc) {
        let fee_account = accounts.get(*fee_index).ok_or(error!(RouterError::JupiterNotARoute))?;
        require_keys_eq!(*fee_account.key, JUPITER_V6, RouterError::JupiterPlatformFee);
        return Ok(());
    }
    if let Some((_, lead)) = JUPITER_V2_ROUTES.iter().find(|(d, _)| d == disc) {
        let at = 8 + lead + 8 + 8 + 2;
        let fees = data.get(at..at + 4).ok_or(error!(RouterError::JupiterNotARoute))?;
        require!(fees == [0u8; 4], RouterError::JupiterPlatformFee);
        return Ok(());
    }
    err!(RouterError::JupiterNotARoute)
}

/// A wallet must be a real address, and never the vault (nobody could collect for it).
fn check_wallet(wallet: &Pubkey, vault: &Pubkey) -> Result<()> {
    require_keys_neq!(*wallet, Pubkey::default(), RouterError::ZeroAddress);
    require_keys_neq!(*wallet, *vault, RouterError::ZeroAddress);
    Ok(())
}

/// Binds the swap to the measured accounts: every WRITABLE token account handed to the swap that `user` owns, or is
/// the delegate of, must be `input` or `output`. A token account the swap can debit with the user's signature is
/// one of those two; anything else (a second wSOL account used as the real source while an empty one is measured)
/// is refused. Works for both token programs without decoding the swap instruction.
fn check_swap_accounts(accounts: &[AccountInfo], user: &Pubkey, input: &Pubkey, output: &Pubkey) -> Result<()> {
    for a in accounts {
        // Native-program accounts can name the user as their authority (stake, vote, program upgrade, lookup table,
        // durable nonce), and the swap holds the user's signature: none may be writable in the swap. The user's wallet
        // is passed read-only anyway (see `execute`), so a system account is refused only when it holds data.
        if a.is_writable && a.key != user {
            let system = a.owner == &NATIVE_PROGRAMS[0];
            if (system && a.data_len() > 0) || (!system && NATIVE_PROGRAMS.contains(a.owner)) {
                return err!(RouterError::ProtectedAccount);
            }
        }
        if a.owner != &anchor_spl::token::ID && a.owner != &anchor_spl::token_2022::ID {
            continue;
        }
        // An SPL multisig the user signs for could authorize spending from accounts it owns, which the owner and
        // delegate checks below would not see. No supported swap needs one, so none may be handed to the swap.
        if a.data_len() == MULTISIG_LEN {
            return err!(RouterError::MultisigNotAllowed);
        }
        if !a.is_writable || a.key == input || a.key == output {
            continue;
        }
        let data = a.try_borrow_data()?;
        if !is_token_account(&data) {
            continue;
        }
        let owner = &data[32..64];
        let has_delegate = u32::from_le_bytes([data[72], data[73], data[74], data[75]]) == 1;
        let delegate = &data[76..108];
        if owner == user.as_ref() || (has_delegate && delegate == user.as_ref()) {
            return err!(RouterError::SwapAccountNotBound);
        }
    }
    Ok(())
}

/// A token account in either token program: 165 bytes (SPL Token), or longer with the Token-2022 account-type byte
/// at offset 165 set to Account (2). Mints (82 bytes, or type byte 1) and multisigs (355 bytes) are not.
fn is_token_account(data: &[u8]) -> bool {
    const LEN: usize = 165;
    data.len() == LEN || (data.len() > LEN && data.len() != MULTISIG_LEN && data[LEN] == 2)
}

/// Size of an SPL multisig account in both token programs (Token-2022 never sizes a token account to this length).
const MULTISIG_LEN: usize = 355;

/// Makes sure `wallet`'s credit account exists, creating it (paid by `payer`) if not. Works even if someone
/// pre-funded the address with lamports. Called only when a wallet is set, never during a swap.
fn ensure_credit<'info>(
    credit: &UncheckedAccount<'info>,
    wallet: Pubkey,
    payer: &Signer<'info>,
    system_program: &Program<'info, System>,
) -> Result<()> {
    let (expected, bump) = Pubkey::find_program_address(&[CREDIT_SEED, wallet.as_ref()], &crate::ID);
    require_keys_eq!(credit.key(), expected, RouterError::WrongCreditAccount);
    let info = credit.to_account_info();
    if info.owner == &crate::ID {
        let c = Credit::try_deserialize(&mut &info.try_borrow_data()?[..])?;
        require_keys_eq!(c.wallet, wallet, RouterError::WrongCreditAccount);
        return Ok(());
    }
    let seeds: &[&[u8]] = &[CREDIT_SEED, wallet.as_ref(), &[bump]];
    let space = 8 + Credit::INIT_SPACE;
    let need = Rent::get()?.minimum_balance(space).saturating_sub(info.lamports());
    if need > 0 {
        invoke(
            &system_instruction::transfer(&payer.key(), &expected, need),
            &[payer.to_account_info(), info.clone(), system_program.to_account_info()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(&expected, space as u64),
        &[info.clone(), system_program.to_account_info()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(&expected, &crate::ID),
        &[info.clone(), system_program.to_account_info()],
        &[seeds],
    )?;
    let c = Credit { wallet, amount: 0, bump };
    let mut data = info.try_borrow_mut_data()?;
    let mut w: &mut [u8] = &mut data[..];
    c.try_serialize(&mut w)?;
    Ok(())
}

/// Adds `amount` to `wallet`'s existing credit account. Read-modify-write on the account's own bytes, so the
/// protocol wallet and a router's fee wallet may be the same address: the second credit reads what the first wrote.
fn add_credit(credit: &UncheckedAccount, wallet: Pubkey, amount: u64) -> Result<()> {
    let (expected, _) = Pubkey::find_program_address(&[CREDIT_SEED, wallet.as_ref()], &crate::ID);
    require_keys_eq!(credit.key(), expected, RouterError::WrongCreditAccount);
    if amount == 0 {
        return Ok(());
    }
    let info = credit.to_account_info();
    require_keys_eq!(*info.owner, crate::ID, RouterError::CreditAccountMissing);
    let mut data = info.try_borrow_mut_data()?;
    let mut c = Credit::try_deserialize(&mut &data[..])?;
    require_keys_eq!(c.wallet, wallet, RouterError::WrongCreditAccount);
    c.amount = c.amount.checked_add(amount).ok_or(RouterError::MathOverflow)?;
    let mut w: &mut [u8] = &mut data[..];
    c.try_serialize(&mut w)?;
    Ok(())
}

// ============================================================================ accounts

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub owner: Pubkey,
    pub pending_owner: Pubkey,
    pub protocol_wallet: Pubkey,
    /// Fee floor, lamports. At most `max_min_fee`.
    pub min_fee: u64,
    /// Cap on the floor, lamports. Set once at initialize; no setter.
    pub max_min_fee: u64,
    /// Sum of all credits; the vault always holds exactly this above its rent reserve.
    pub total_credited: u64,
    pub bump: u8,
    pub vault_bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Router {
    pub owner: Pubkey,
    pub pending_owner: Pubkey,
    pub fee_wallet: Pubkey,
    /// Fixed at creation; no setter.
    pub trader_fee_bps: u16,
    pub salt: [u8; 32],
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Credit {
    pub wallet: Pubkey,
    /// Lamports `wallet` can collect.
    pub amount: u64,
    pub bump: u8,
}

// ============================================================================ instruction contexts

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: lamport-only PDA (system-owned, no data); its address is fixed by the seeds.
    #[account(mut, seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the protocol wallet's credit PDA; address checked and account created in `ensure_credit`.
    #[account(mut)]
    pub protocol_credit: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ RouterError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::AlphabrosRouter>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ RouterError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(fee_wallet: Pubkey, trader_fee_bps: u16, salt: [u8; 32])]
pub struct CreateRouter<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(init, payer = owner, space = 8 + Router::INIT_SPACE, seeds = [ROUTER_SEED, owner.key().as_ref(), salt.as_ref()], bump)]
    pub router: Account<'info, Router>,
    /// CHECK: only its address is compared (a wallet may never be the vault).
    #[account(seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the fee wallet's credit PDA; address checked and account created in `ensure_credit`.
    #[account(mut)]
    pub fee_credit: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RouterOwnerOnly<'info> {
    pub owner: Signer<'info>,
    #[account(mut, has_one = owner @ RouterError::NotOwner)]
    pub router: Account<'info, Router>,
}

#[derive(Accounts)]
pub struct SetFeeWallet<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut, has_one = owner @ RouterError::NotOwner)]
    pub router: Account<'info, Router>,
    /// CHECK: only its address is compared (a wallet may never be the vault).
    #[account(seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the new wallet's credit PDA; address checked and account created in `ensure_credit`.
    #[account(mut)]
    pub credit: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptRouterOwnership<'info> {
    pub new_owner: Signer<'info>,
    #[account(mut, constraint = router.pending_owner == new_owner.key() @ RouterError::NotPendingOwner)]
    pub router: Account<'info, Router>,
}

#[derive(Accounts)]
pub struct ConfigOwnerOnly<'info> {
    pub owner: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = owner @ RouterError::NotOwner)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct SetProtocolWallet<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = owner @ RouterError::NotOwner)]
    pub config: Account<'info, Config>,
    /// CHECK: only its address is compared (a wallet may never be the vault).
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the new wallet's credit PDA; address checked and account created in `ensure_credit`.
    #[account(mut)]
    pub credit: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptConfigOwnership<'info> {
    pub new_owner: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, constraint = config.pending_owner == new_owner.key() @ RouterError::NotPendingOwner)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    pub router: Box<Account<'info, Router>>,
    /// CHECK: lamport-only PDA, address fixed by the seeds.
    #[account(mut, seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the protocol wallet's credit PDA (created when the wallet was set); checked in `add_credit`.
    #[account(mut)]
    pub protocol_credit: UncheckedAccount<'info>,
    /// CHECK: the router fee wallet's credit PDA (created when the wallet was set); checked in `add_credit`; may
    /// equal `protocol_credit`.
    #[account(mut)]
    pub trader_credit: UncheckedAccount<'info>,
    /// The user's token account the swap pays from.
    #[account(mut, constraint = input_account.owner == user.key() @ RouterError::NotUsersAccount)]
    pub input_account: Box<InterfaceAccount<'info, TokenAccount>>,
    /// The user's token account the swap pays into.
    #[account(mut, constraint = output_account.owner == user.key() @ RouterError::NotUsersAccount)]
    pub output_account: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: any executable program except the blocked ones; checked in `check_venue` before any call.
    #[account(executable)]
    pub swap_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Collect<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: lamport-only PDA, address fixed by the seeds.
    #[account(mut, seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [CREDIT_SEED, wallet.key().as_ref()], bump = credit.bump, constraint = credit.wallet == wallet.key() @ RouterError::WrongCreditAccount)]
    pub credit: Account<'info, Credit>,
    /// CHECK: receives the lamports; must be the credit's wallet (checked on `credit`).
    #[account(mut)]
    pub wallet: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ============================================================================ events

#[event]
pub struct Initialized {
    pub owner: Pubkey,
    pub protocol_wallet: Pubkey,
    pub min_fee: u64,
    pub max_min_fee: u64,
}

#[event]
pub struct RouterCreated {
    pub router: Pubkey,
    pub owner: Pubkey,
    pub fee_wallet: Pubkey,
    pub trader_fee_bps: u16,
    pub salt: [u8; 32],
}

#[event]
pub struct FeeWalletSet {
    pub router: Pubkey,
    pub wallet: Pubkey,
}

#[event]
pub struct MinFeeSet {
    pub lamports: u64,
}

#[event]
pub struct ProtocolWalletSet {
    pub wallet: Pubkey,
}

#[event]
pub struct Executed {
    pub user: Pubkey,
    pub router: Pubkey,
    pub input_mint: Pubkey,
    pub output_mint: Pubkey,
    pub spent: u64,
    pub received: u64,
    pub fee: u64,
    pub protocol_fee: u64,
    pub trader_fee: u64,
}

#[event]
pub struct Collected {
    pub wallet: Pubkey,
    pub amount: u64,
}

// ============================================================================ errors

#[error_code]
pub enum RouterError {
    #[msg("Address must not be zero or the vault")]
    ZeroAddress,
    #[msg("Value above its cap")]
    AboveCap,
    #[msg("Only the program's upgrade authority can initialize")]
    NotUpgradeAuthority,
    #[msg("Signer is not the owner")]
    NotOwner,
    #[msg("Signer is not the pending owner")]
    NotPendingOwner,
    #[msg("Swap deadline passed")]
    Expired,
    #[msg("min_out must be above zero")]
    ZeroMinOut,
    #[msg("Input and output mints are the same")]
    SameToken,
    #[msg("Neither side is wSOL, so the trade cannot be priced")]
    UnpricedPair,
    #[msg("This program can never be a swap venue (the router itself or a native program)")]
    VenueNotAllowed,
    #[msg("Token account does not belong to the signer")]
    NotUsersAccount,
    #[msg("Output below min_out")]
    InsufficientOutput,
    #[msg("Exact fee is above max_fee")]
    FeeTooLow,
    #[msg("Wrong credit account")]
    WrongCreditAccount,
    #[msg("Arithmetic overflow")]
    MathOverflow,
    #[msg("The swap was handed a writable token account of the user's other than the measured input and output")]
    SwapAccountNotBound,
    #[msg("Nothing was spent from the measured input account")]
    ZeroInput,
    #[msg("More input was spent than max_input")]
    InputTooHigh,
    #[msg("The wallet's credit account does not exist yet")]
    CreditAccountMissing,
    #[msg("An SPL multisig account may not be handed to the swap")]
    MultisigNotAllowed,
    #[msg("The swap changed the owner, delegate or close authority of the measured input or output account")]
    AccountAuthorityChanged,
    #[msg("Jupiter instruction is not a route")]
    JupiterNotARoute,
    #[msg("Jupiter's platform fee must be off")]
    JupiterPlatformFee,
    #[msg("A writable account owned by a native program, or a system account holding data, may not be handed to the swap")]
    ProtectedAccount,
    #[msg("The swap assigned the wallet to a program or gave it data")]
    WalletTampered,
    #[msg("The swap took more of the wallet's SOL than max_wallet_spend")]
    WalletSpendTooHigh,
    #[msg("The swap took lamports from the measured input or output account beyond its token amount")]
    AccountLamportsTaken,
}
