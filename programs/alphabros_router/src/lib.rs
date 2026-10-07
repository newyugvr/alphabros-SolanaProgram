//! Alphabros V4 fee router for Solana.
//!
//! One config, owned by the protocol (a Squads vault). Users swap through any venue they choose (Jupiter v6, another
//! aggregator, a DEX, a bonding curve): the program runs the swap by CPI with the user's own token accounts and
//! signature, measures what actually moved on the user's accounts (the SOL side net of the wallet's change), and
//! charges an exact fee in SOL:
//!
//!     fee = max(min_fee, ceil(SOL side x fee_bps / 10_000))
//!
//! never above the `max_fee` the user signed. The owner sets `fee_bps` (never above 0.5%, a constant). A trade may
//! name a community and a referral: one payee share of the fee (never above 60%, a constant) goes whole to the one
//! named, split by the owner's community split when both are; the protocol gets the rest. Communities and referrals
//! register with the SAME EIP-712 signature (the owner's EVM key) as on the EVM router, so one signature serves every
//! chain. Every fee is credited in the program and each wallet collects its own credit later; nothing is pushed during
//! a swap.
//!
//! Venues are permissionless: the user signs the transaction and so chooses the venue. What makes a venue safe to call
//! is what `execute_v4` enforces around it: the swap is bound to the measured accounts (no other writable token account
//! the user owns, delegates or can close; no writable mint naming the user as an authority, and no other account of a
//! mint through which the user can act on accounts it does not own), only the user's signature is passed on, native
//! program accounts and the wallet are out of reach (the wallet only within a signed `max_wallet_spend`), no approval
//! or authority change survives, spent <= max_input, received >= min_out. The router itself and the native programs
//! are never venues; when the venue is Jupiter v6 its own platform fee must be off. A venue can still act on other
//! programs' accounts the user hands it and signs for: the user's choice of venue is the trust boundary.

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

pub const BPS: u64 = 10_000;
/// Most wallet SOL a swap may be signed to spend (`max_wallet_spend`): 100 SOL.
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

pub const CONFIG_V4_SEED: &[u8] = b"config_v4";
pub const VAULT_V4_SEED: &[u8] = b"vault_v4";
pub const CREDIT_V4_SEED: &[u8] = b"credit_v4";
pub const PAYEE_SEED: &[u8] = b"payee";
/// Most the V4 fee rate can ever be: 0.5% of the trade's SOL side. Fixed forever.
pub const MAX_FEE_BPS_V4: u16 = 50;
/// Most the V4 payee share (community + referral together) can ever be: 60% of the fee. Fixed forever.
pub const MAX_PAYEE_SHARE_BPS: u16 = 6_000;
pub const COMMUNITY: u8 = 1;
pub const REFERRAL: u8 = 2;
/// The EVM V4 router's EIP-712 domain separator ("Alphabros", "4", its address 0xF5502aa5…de90; no chain ID). The
/// same on every EVM chain, so one Registration signature serves every EVM chain and Solana.
pub const EIP712_DOMAIN: [u8; 32] = hex32("93f6f0660059798bc0d68765462e6e0bef950fb63219a50322304039d684ea44");
/// keccak256("Registration(uint8 kind,address owner,bytes32 name,address wallet,bytes32 solanaWallet,uint64 version)")
pub const REGISTRATION_TYPEHASH: [u8; 32] = hex32("be037f4fad9aa46fa7a3c389bb1b2e428a0890d414d12a158f625e8b0d90e06d");
/// secp256k1 n / 2: signatures with a higher s are refused (no malleable duplicates), as on EVM.
const HALF_N: [u8; 32] = hex32("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

const fn hex32(h: &str) -> [u8; 32] {
    let b = h.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex"),
    }
}

#[program]
pub mod alphabros_router {
    use super::*;


    /// One-time V4 setup, by the program's upgrade authority only. The fee rate (at most 0.5%), the payee share (at
    /// most 60% of the fee) and the community split (when a trade names both payees) are the starting values; the
    /// owner changes them later, never above the caps. Creates the protocol wallet's V4 credit account.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_v4(
        ctx: Context<InitializeV4>,
        owner: Pubkey,
        protocol_wallet: Pubkey,
        min_fee: u64,
        max_min_fee: u64,
        fee_bps: u16,
        payee_share_bps: u16,
        community_split_bps: u16,
    ) -> Result<()> {
        require_keys_neq!(owner, Pubkey::default(), RouterError::ZeroAddress);
        check_wallet(&protocol_wallet, &ctx.accounts.vault.key())?;
        require!(min_fee <= max_min_fee, RouterError::AboveCap);
        check_v4_rates(fee_bps, payee_share_bps, community_split_bps)?;
        let config = &mut ctx.accounts.config;
        config.owner = owner;
        config.pending_owner = Pubkey::default();
        config.protocol_wallet = protocol_wallet;
        config.min_fee = min_fee;
        config.max_min_fee = max_min_fee;
        config.fee_bps = fee_bps;
        config.payee_share_bps = payee_share_bps;
        config.community_split_bps = community_split_bps;
        config.total_credited = 0;
        config.bump = ctx.bumps.config;
        config.vault_bump = ctx.bumps.vault;
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
        ensure_credit_in(CREDIT_V4_SEED, &ctx.accounts.protocol_credit, protocol_wallet, &ctx.accounts.payer, &ctx.accounts.system_program)?;
        emit!(V4Settings { owner, protocol_wallet, min_fee, fee_bps, payee_share_bps, community_split_bps });
        Ok(())
    }

    /// The fee rate, in basis points of the trade's SOL side (30 = 0.3%); at most 0.5%. A user signs `max_fee`, so a
    /// raise never takes more than that.
    pub fn set_fee_bps_v4(ctx: Context<ConfigV4OwnerOnly>, fee_bps: u16) -> Result<()> {
        let c = &mut ctx.accounts.config;
        check_v4_rates(fee_bps, c.payee_share_bps, c.community_split_bps)?;
        c.fee_bps = fee_bps;
        emit_v4_settings(c);
        Ok(())
    }

    /// The payee share (basis points of the fee, at most 60%) and the community's part of it when a trade names both
    /// payees (basis points of the share). Applies to fees settled from now on.
    pub fn set_shares_v4(ctx: Context<ConfigV4OwnerOnly>, payee_share_bps: u16, community_split_bps: u16) -> Result<()> {
        let c = &mut ctx.accounts.config;
        check_v4_rates(c.fee_bps, payee_share_bps, community_split_bps)?;
        c.payee_share_bps = payee_share_bps;
        c.community_split_bps = community_split_bps;
        emit_v4_settings(c);
        Ok(())
    }

    /// The floor, lamports; at most the cap fixed at `initialize_v4`.
    pub fn set_min_fee_v4(ctx: Context<ConfigV4OwnerOnly>, lamports: u64) -> Result<()> {
        let c = &mut ctx.accounts.config;
        require!(lamports <= c.max_min_fee, RouterError::AboveCap);
        c.min_fee = lamports;
        emit_v4_settings(c);
        Ok(())
    }

    /// Future protocol fees go to `wallet`; what the old wallet earned stays its own to collect. Creates the new
    /// wallet's V4 credit account (paid by the owner) so no swap ever pays for it.
    pub fn set_protocol_wallet_v4(ctx: Context<SetProtocolWalletV4>, wallet: Pubkey) -> Result<()> {
        check_wallet(&wallet, &ctx.accounts.vault.key())?;
        ensure_credit_in(CREDIT_V4_SEED, &ctx.accounts.wallet_credit, wallet, &ctx.accounts.owner, &ctx.accounts.system_program)?;
        let c = &mut ctx.accounts.config;
        c.protocol_wallet = wallet;
        emit_v4_settings(c);
        Ok(())
    }

    pub fn transfer_ownership_v4(ctx: Context<ConfigV4OwnerOnly>, new_owner: Pubkey) -> Result<()> {
        ctx.accounts.config.pending_owner = new_owner;
        Ok(())
    }

    pub fn accept_ownership_v4(ctx: Context<AcceptOwnershipV4>) -> Result<()> {
        let c = &mut ctx.accounts.config;
        c.owner = c.pending_owner;
        c.pending_owner = Pubkey::default();
        Ok(())
    }

    /// Stores a community's or referral's signed registration (anyone may send it; only the owner's EVM signature,
    /// the same EIP-712 message the EVM router checks, makes it valid). The payee account is created on first use,
    /// paid by `payer`. A version at or below the stored one changes nothing; a higher one moves the payout wallet
    /// (what is already earned is then collected to the new wallet).
    pub fn register_payee(ctx: Context<RegisterPayee>, reg: Registration) -> Result<()> {
        require!(reg.kind == COMMUNITY || reg.kind == REFERRAL, RouterError::BadRegistration);
        require!(reg.owner != [0u8; 20] && reg.version > 0, RouterError::BadRegistration);
        require!(reg.solana_wallet != Pubkey::default(), RouterError::BadRegistration);
        let id = payee_id(reg.kind, &reg.owner, &reg.name);
        let (expected, bump) = Pubkey::find_program_address(&[PAYEE_SEED, &id], &crate::ID);
        let info = ctx.accounts.payee.to_account_info();
        require_keys_eq!(info.key(), expected, RouterError::PayeeMismatch);
        require!(reg.solana_wallet != expected && reg.solana_wallet != ctx.accounts.vault.key(), RouterError::BadRegistration);

        if info.owner == &crate::ID {
            let stored = Payee::try_deserialize(&mut &info.try_borrow_data()?[..])?;
            if reg.version <= stored.version {
                return Ok(()); // this version, or a newer one, is already here
            }
        }
        verify_registration(&reg)?;

        if info.owner != &crate::ID {
            let space = 8 + Payee::INIT_SPACE;
            let seeds: &[&[u8]] = &[PAYEE_SEED, &id, &[bump]];
            let need = Rent::get()?.minimum_balance(space).saturating_sub(info.lamports());
            if need > 0 {
                invoke(
                    &system_instruction::transfer(&ctx.accounts.payer.key(), &expected, need),
                    &[ctx.accounts.payer.to_account_info(), info.clone(), ctx.accounts.system_program.to_account_info()],
                )?;
            }
            invoke_signed(&system_instruction::allocate(&expected, space as u64), &[info.clone(), ctx.accounts.system_program.to_account_info()], &[seeds])?;
            invoke_signed(&system_instruction::assign(&expected, &crate::ID), &[info.clone(), ctx.accounts.system_program.to_account_info()], &[seeds])?;
            let p = Payee { kind: reg.kind, owner: reg.owner, name: reg.name, wallet: reg.solana_wallet, version: reg.version, amount: 0, bump };
            let mut data = info.try_borrow_mut_data()?;
            let mut w: &mut [u8] = &mut data[..];
            p.try_serialize(&mut w)?;
        } else {
            let mut data = info.try_borrow_mut_data()?;
            let mut p = Payee::try_deserialize(&mut &data[..])?;
            p.wallet = reg.solana_wallet;
            p.version = reg.version;
            let mut w: &mut [u8] = &mut data[..];
            p.try_serialize(&mut w)?;
        }
        emit!(PayeeRegistered { id, kind: reg.kind, owner: reg.owner, name: reg.name, wallet: reg.solana_wallet, version: reg.version });
        Ok(())
    }

    /// The swap: the user signs `max_wallet_spend` (0 keeps the wallet read-only; above zero, only bonding-curve style
    /// venues that trade the wallet's own SOL need it, and the wallet must stay a plain system account), the fee
    /// (max(floor, SOL side x fee rate), at most `max_fee`), and the payee share to the community and/or referral the
    /// trade names. Each named payee must be registered as its kind with exactly the wallet the trade expects, or the
    /// swap reverts; a payee whose wallet is the user or the protocol wallet earns nothing. Pass the payee accounts as
    /// `community_payee` / `referral_payee` (or none).
    #[allow(clippy::too_many_arguments)]
    pub fn execute_v4<'info>(
        ctx: Context<'info, ExecuteV4<'info>>,
        min_out: u64,
        max_fee: u64,
        max_input: u64,
        max_wallet_spend: u64,
        deadline: i64,
        swap_data: Vec<u8>,
        community: Option<Party>,
        referral: Option<Party>,
    ) -> Result<()> {
        require!(max_wallet_spend <= MAX_WALLET_SPEND, RouterError::AboveCap);
        let user = ctx.accounts.user.key();
        let protocol_wallet = ctx.accounts.config.protocol_wallet;
        // Cross-check both payees before anything moves.
        let comm = resolve_payee(ctx.accounts.community_payee.as_ref(), community.as_ref(), COMMUNITY, &user, &protocol_wallet)?;
        let refr = resolve_payee(ctx.accounts.referral_payee.as_ref(), referral.as_ref(), REFERRAL, &user, &protocol_wallet)?;

        let m = measured_swap(
            &ctx.accounts.user,
            &mut ctx.accounts.input_account,
            &mut ctx.accounts.output_account,
            &ctx.accounts.swap_program,
            ctx.remaining_accounts,
            SwapLimits { min_out, max_input, max_wallet_spend, deadline },
            swap_data,
        )?;

        let c = &ctx.accounts.config;
        let sol_side = core::cmp::max(
            if m.in_mint == WSOL_MINT { m.spent } else { 0 },
            if m.out_mint == WSOL_MINT { m.received } else { 0 },
        );
        let fee = core::cmp::max(c.min_fee, pct(sol_side, c.fee_bps as u64)?);
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
        // One payee share: all of it to the payee that earns, split by the community split when both do.
        let pool = (fee as u128 * c.payee_share_bps as u128 / BPS as u128) as u64;
        let (community_fee, referral_fee) = match (comm.earns, refr.earns) {
            (true, true) => {
                let cf = (pool as u128 * c.community_split_bps as u128 / BPS as u128) as u64;
                (cf, pool - cf)
            }
            (true, false) => (pool, 0),
            (false, true) => (0, pool),
            (false, false) => (0, 0),
        };
        let protocol_fee = fee - community_fee - referral_fee;
        if community_fee > 0 {
            add_payee_credit(ctx.accounts.community_payee.as_ref(), community_fee)?;
        }
        if referral_fee > 0 {
            add_payee_credit(ctx.accounts.referral_payee.as_ref(), referral_fee)?;
        }
        add_credit_in(CREDIT_V4_SEED, &ctx.accounts.protocol_credit, protocol_wallet, protocol_fee)?;
        let config = &mut ctx.accounts.config;
        config.total_credited = config.total_credited.checked_add(fee).ok_or(RouterError::MathOverflow)?;

        emit!(FeePaid {
            user,
            community_id: comm.id,
            referral_id: refr.id,
            community_wallet: if community_fee > 0 { comm.wallet } else { Pubkey::default() },
            referral_wallet: if referral_fee > 0 { refr.wallet } else { Pubkey::default() },
            fee,
            protocol_fee,
            community_fee,
            referral_fee,
            input_mint: m.in_mint,
            output_mint: m.out_mint,
            spent: m.spent,
            received: m.received,
        });
        Ok(())
    }

    /// Pays a community or referral everything it earned, to its current payout wallet. Anyone may trigger it.
    pub fn collect_payee(ctx: Context<CollectPayee>) -> Result<()> {
        let amount = ctx.accounts.payee.amount;
        if amount == 0 {
            return Ok(());
        }
        ctx.accounts.payee.amount = 0;
        pay_from_v4_vault(&mut ctx.accounts.config, &ctx.accounts.vault, &ctx.accounts.wallet, &ctx.accounts.system_program, amount)?;
        emit!(Collected { wallet: ctx.accounts.wallet.key(), amount });
        Ok(())
    }

    /// Pays a wallet its V4 credit (the protocol wallet's fees). Anyone may trigger it; the lamports only go to `wallet`.
    pub fn collect_v4(ctx: Context<CollectV4>) -> Result<()> {
        let amount = ctx.accounts.credit.amount;
        if amount == 0 {
            return Ok(());
        }
        ctx.accounts.credit.amount = 0;
        pay_from_v4_vault(&mut ctx.accounts.config, &ctx.accounts.vault, &ctx.accounts.wallet, &ctx.accounts.system_program, amount)?;
        emit!(Collected { wallet: ctx.accounts.wallet.key(), amount });
        Ok(())
    }
}

// ============================================================================ V4 helpers

fn check_v4_rates(fee_bps: u16, payee_share_bps: u16, community_split_bps: u16) -> Result<()> {
    require!(fee_bps <= MAX_FEE_BPS_V4, RouterError::AboveCap);
    require!(payee_share_bps <= MAX_PAYEE_SHARE_BPS, RouterError::AboveCap);
    require!(community_split_bps as u64 <= BPS, RouterError::AboveCap);
    Ok(())
}

fn emit_v4_settings(c: &ConfigV4) {
    emit!(V4Settings {
        owner: c.owner,
        protocol_wallet: c.protocol_wallet,
        min_fee: c.min_fee,
        fee_bps: c.fee_bps,
        payee_share_bps: c.payee_share_bps,
        community_split_bps: c.community_split_bps,
    });
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    solana_keccak_hasher::hashv(parts).to_bytes()
}

/// A 32-byte ABI word holding `bytes` right-aligned (uint8, address, uint64).
fn word(bytes: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(bytes);
    w
}

/// keccak256(abi.encode(uint8 kind, address owner, bytes32 name)): the EVM router's `payeeId`, the same ID everywhere.
pub fn payee_id(kind: u8, owner: &[u8; 20], name: &[u8; 32]) -> [u8; 32] {
    keccak(&[&word(&[kind]), &word(owner), name])
}

/// The EIP-712 digest of `reg`, exactly as the EVM router's `registrationDigest`.
pub fn registration_digest(reg: &Registration) -> [u8; 32] {
    let struct_hash = keccak(&[
        &REGISTRATION_TYPEHASH,
        &word(&[reg.kind]),
        &word(&reg.owner),
        &reg.name,
        &word(&reg.evm_wallet),
        reg.solana_wallet.as_ref(),
        &word(&reg.version.to_be_bytes()),
    ]);
    keccak(&[&[0x19, 0x01], &EIP712_DOMAIN, &struct_hash])
}

/// The owner's (r, s, v) signature over the registration: low s, v 27/28, signer = `reg.owner`.
fn verify_registration(reg: &Registration) -> Result<()> {
    let sig = &reg.signature;
    let v = sig[64];
    require!(v == 27 || v == 28, RouterError::BadSignature);
    require!(sig[32..64] <= HALF_N[..], RouterError::BadSignature);
    let digest = registration_digest(reg);
    let pubkey = solana_secp256k1_recover::secp256k1_recover(&digest, v - 27, &sig[..64])
        .map_err(|_| error!(RouterError::BadSignature))?;
    let addr = keccak(&[&pubkey.to_bytes()]);
    require!(addr[12..] == reg.owner[..], RouterError::BadSignature);
    Ok(())
}

/// A payee a trade names, after the cross-check.
struct Resolved {
    id: [u8; 32],
    wallet: Pubkey,
    earns: bool,
}

/// Checks the payee account against the party the trade names: the PDA of its ID, owned by this program, of `kind`,
/// with exactly the expected wallet. No party: nobody (the account, if passed, is ignored).
fn resolve_payee(account: Option<&UncheckedAccount>, party: Option<&Party>, kind: u8, user: &Pubkey, protocol_wallet: &Pubkey) -> Result<Resolved> {
    let Some(party) = party else { return Ok(Resolved { id: [0u8; 32], wallet: Pubkey::default(), earns: false }) };
    let info = account.ok_or(error!(RouterError::PayeeMismatch))?.to_account_info();
    let (expected, _) = Pubkey::find_program_address(&[PAYEE_SEED, &party.id], &crate::ID);
    require_keys_eq!(info.key(), expected, RouterError::PayeeMismatch);
    require_keys_eq!(*info.owner, crate::ID, RouterError::PayeeMismatch);
    let p = Payee::try_deserialize(&mut &info.try_borrow_data()?[..]).map_err(|_| error!(RouterError::PayeeMismatch))?;
    require!(p.kind == kind && p.wallet == party.wallet, RouterError::PayeeMismatch);
    let earns = p.wallet != *user && p.wallet != *protocol_wallet;
    Ok(Resolved { id: party.id, wallet: p.wallet, earns })
}

fn add_payee_credit(account: Option<&UncheckedAccount>, amount: u64) -> Result<()> {
    let info = account.ok_or(error!(RouterError::PayeeMismatch))?.to_account_info();
    let mut data = info.try_borrow_mut_data()?;
    let mut p = Payee::try_deserialize(&mut &data[..])?;
    p.amount = p.amount.checked_add(amount).ok_or(RouterError::MathOverflow)?;
    let mut w: &mut [u8] = &mut data[..];
    p.try_serialize(&mut w)?;
    Ok(())
}

fn pay_from_v4_vault<'info>(
    config: &mut Account<'info, ConfigV4>,
    vault: &UncheckedAccount<'info>,
    wallet: &UncheckedAccount<'info>,
    system_program: &Program<'info, System>,
    amount: u64,
) -> Result<()> {
    config.total_credited = config.total_credited.checked_sub(amount).ok_or(RouterError::MathOverflow)?;
    let vault_bump = config.vault_bump;
    invoke_signed(
        &system_instruction::transfer(&vault.key(), &wallet.key(), amount),
        &[vault.to_account_info(), wallet.to_account_info(), system_program.to_account_info()],
        &[&[VAULT_V4_SEED, &[vault_bump]]],
    )
    .map_err(Into::into)
}

// ============================================================================ helpers

/// What a swap may do: the user's signed limits.
struct SwapLimits {
    min_out: u64,
    max_input: u64,
    max_wallet_spend: u64,
    deadline: i64,
}

/// What a swap actually moved, measured on the user's accounts (the SOL side NET of the wallet's change).
struct Measured {
    in_mint: Pubkey,
    out_mint: Pubkey,
    spent: u64,
    received: u64,
}

/// The swap shared by every version: checks the venue and the accounts handed to it, runs it with only the user's
/// signature (the wallet writable only within a signed wallet spend), then measures what moved and enforces the
/// limits. Settling the fee is the caller's.
fn measured_swap<'info>(
    user_acc: &Signer<'info>,
    input: &mut Box<InterfaceAccount<'info, TokenAccount>>,
    output: &mut Box<InterfaceAccount<'info, TokenAccount>>,
    venue: &UncheckedAccount<'info>,
    remaining: &[AccountInfo<'info>],
    limits: SwapLimits,
    swap_data: Vec<u8>,
) -> Result<Measured> {
    let SwapLimits { min_out, max_input, max_wallet_spend, deadline } = limits;
    require!(Clock::get()?.unix_timestamp <= deadline, RouterError::Expired);
    require!(min_out > 0, RouterError::ZeroMinOut);

    let in_mint = input.mint;
    let out_mint = output.mint;
    require_keys_neq!(in_mint, out_mint, RouterError::SameToken);
    require!(in_mint == WSOL_MINT || out_mint == WSOL_MINT, RouterError::UnpricedPair);

    let swap_program = venue.key();
    check_venue(&swap_program, &swap_data, remaining)?;

    let user = user_acc.key();
    let input_key = input.key();
    let output_key = output.key();
    check_swap_accounts(remaining, &user, &input_key, &output_key)?;

    let in_before = input.amount;
    let wallet_before = user_acc.lamports();
    let out_before = output.amount;
    let in_auth = authorities(&input);
    let out_auth = authorities(&output);
    let in_excess = excess_lamports(&input);
    let out_excess = excess_lamports(&output);

    // The swap. Only the user's signature is passed on (any other signer in the transaction is dropped), and the
    // user's wallet is read-only unless the user signed a wallet spend (`max_wallet_spend`): without one the swap can use
    // the user's signature, never move the wallet's SOL.
    let wallet_writable = max_wallet_spend > 0;
    let metas: Vec<AccountMeta> = remaining
        .iter()
        .map(|a| AccountMeta {
            pubkey: *a.key,
            is_signer: a.is_signer && *a.key == user,
            is_writable: a.is_writable && (*a.key != user || wallet_writable),
        })
        .collect();
    let mut infos: Vec<AccountInfo<'info>> = remaining.to_vec();
    infos.push(venue.to_account_info());
    invoke(&Instruction { program_id: swap_program, accounts: metas, data: swap_data }, &infos)?;

    input.reload()?;
    output.reload()?;
    // The swap held the user's signature: it may move tokens, but must leave both accounts' owner, delegate and
    // close authority exactly as they were (no approval or authority change can outlive the transaction).
    require!(authorities(&input) == in_auth, RouterError::AccountAuthorityChanged);
    require!(authorities(&output) == out_auth, RouterError::AccountAuthorityChanged);
    // Neither measured account may lose SOL that is not its token amount (rent, surplus lamports, unsynced lamports
    // of a wSOL account): a swap could otherwise withdraw them, or sync them into the measured amount.
    require!(excess_lamports(&input) >= in_excess, RouterError::AccountLamportsTaken);
    require!(excess_lamports(&output) >= out_excess, RouterError::AccountLamportsTaken);
    // The wallet: still a plain system account (no Assign, no Allocate), and at most `max_wallet_spend` lamports
    // gone.
    let wallet = user_acc.to_account_info();
    require!(wallet.owner == &NATIVE_PROGRAMS[0] && wallet.data_is_empty(), RouterError::WalletTampered);
    let wallet_after = wallet.lamports();
    require!(wallet_before.saturating_sub(wallet_after) <= max_wallet_spend, RouterError::WalletSpendTooHigh);
    // The SOL side is measured NET: the wSOL account's change plus the wallet's change, signed, so a loss on one
    // can never hide behind a gain on the other. The token side is the measured account's own change.
    let wallet_change = wallet_after as i128 - wallet_before as i128;
    let (spent, received) = if in_mint == WSOL_MINT {
        let sol_change = input.amount as i128 - in_before as i128 + wallet_change;
        let spent = u64::try_from((-sol_change).max(0)).map_err(|_| error!(RouterError::MathOverflow))?;
        (spent, output.amount.saturating_sub(out_before))
    } else {
        let sol_change = output.amount as i128 - out_before as i128 + wallet_change;
        let received = u64::try_from(sol_change.max(0)).map_err(|_| error!(RouterError::MathOverflow))?;
        (in_before.saturating_sub(input.amount), received)
    };
    require!(spent > 0, RouterError::ZeroInput);
    require!(spent <= max_input, RouterError::InputTooHigh);
    require!(received >= min_out, RouterError::InsufficientOutput);
    Ok(Measured { in_mint, out_mint, spent, received })
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
    // Mints handed to the swap over which the user holds any power with its signature. Two cases:
    //  - a WRITABLE mint naming the user anywhere (mint or freeze authority, or any Token-2022 extension authority:
    //    mint close, transfer fee, transfer hook, pausable, interest rate, metadata, group, ...) is refused outright,
    //    since every mint-level action needs the mint writable;
    //  - a mint, even read-only, through which the user can act on OTHER people's accounts (freeze authority,
    //    permanent delegate, transfer-fee withdraw-withheld authority, confidential-transfer approval authority):
    //    no writable account of that mint may reach the swap, except the measured input and output.
    let mut user_mints: Vec<Pubkey> = Vec::new();
    for a in accounts {
        if a.owner != &anchor_spl::token::ID && a.owner != &anchor_spl::token_2022::ID {
            continue;
        }
        let data = a.try_borrow_data()?;
        if !is_mint(&data) {
            continue;
        }
        if a.is_writable && mint_names_user(&data, user) {
            return err!(RouterError::AuthorityExposed);
        }
        if mint_gives_account_power(&data, user) {
            user_mints.push(*a.key);
        }
    }
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
        // Any other writable token account the user can act on with its signature: as owner, delegate, or close
        // authority (closing it sends its lamports, a wSOL account's whole balance, wherever the venue chooses).
        let owner = &data[32..64];
        let delegate = coption_key(&data, 72);
        let close_authority = coption_key(&data, 129);
        if owner == user.as_ref() || delegate == Some(*user) || close_authority == Some(*user) {
            return err!(RouterError::SwapAccountNotBound);
        }
        // ...or of a mint through which the user can act on other people's accounts.
        let mint = key_at(&data, 0);
        if user_mints.contains(&mint) {
            return err!(RouterError::AuthorityExposed);
        }
    }
    Ok(())
}

/// The key of a `COption<Pubkey>` at `at` (u32 tag, then 32 bytes), if set.
fn coption_key(data: &[u8], at: usize) -> Option<Pubkey> {
    if data.len() < at + 36 || u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) != 1 {
        return None;
    }
    Some(key_at(data, at + 4))
}
fn key_at(data: &[u8], at: usize) -> Pubkey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&data[at..at + 32]);
    Pubkey::new_from_array(k)
}

/// A mint in either token program: 82 bytes (SPL Token), or longer with the Token-2022 account-type byte at 165 = 1.
fn is_mint(data: &[u8]) -> bool {
    data.len() == 82 || (data.len() > 165 && data.len() != MULTISIG_LEN && data[165] == 1)
}

/// The key at `offset` inside a Token-2022 mint's extension of type `ext` (TLV entries after the account-type byte),
/// if the mint has that extension and the key is set.
fn extension_key(data: &[u8], ext: u16, offset: usize) -> Option<Pubkey> {
    if data.len() <= 166 {
        return None;
    }
    let mut i = 166;
    while i + 4 <= data.len() {
        let ty = u16::from_le_bytes([data[i], data[i + 1]]);
        let len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        let start = i + 4;
        if ty == 0 || start + len > data.len() {
            return None; // end of the extensions (or malformed)
        }
        if ty == ext && offset + 32 <= len {
            let k = key_at(data, start + offset);
            return if k == Pubkey::default() { None } else { Some(k) };
        }
        i = start + len;
    }
    None
}

/// The user is the mint's mint or freeze authority, or its key appears anywhere in the Token-2022 extensions (every
/// extension authority, including ones added to the token program later).
fn mint_names_user(data: &[u8], user: &Pubkey) -> bool {
    if coption_key(data, 0) == Some(*user) || coption_key(data, 46) == Some(*user) {
        return true;
    }
    data.len() > 166 && data[166..].windows(32).any(|w| w == user.as_ref())
}

/// Token-2022 extension types whose authority acts on token accounts of the mint while the mint is read-only.
const EXT_TRANSFER_FEE_CONFIG: u16 = 1; // withdraw_withheld_authority at offset 32
const EXT_CONFIDENTIAL_TRANSFER_MINT: u16 = 4; // authority at offset 0 (approves accounts)
const EXT_PERMANENT_DELEGATE: u16 = 12; // delegate at offset 0

/// Through this mint the user can act on accounts it does not own: freeze authority, permanent delegate,
/// transfer-fee withdraw-withheld authority, or confidential-transfer approval authority.
fn mint_gives_account_power(data: &[u8], user: &Pubkey) -> bool {
    let me = Some(*user);
    coption_key(data, 46) == me
        || extension_key(data, EXT_PERMANENT_DELEGATE, 0) == me
        || extension_key(data, EXT_TRANSFER_FEE_CONFIG, 32) == me
        || extension_key(data, EXT_CONFIDENTIAL_TRANSFER_MINT, 0) == me
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
fn ensure_credit_in<'info>(
    seed: &[u8],
    credit: &UncheckedAccount<'info>,
    wallet: Pubkey,
    payer: &Signer<'info>,
    system_program: &Program<'info, System>,
) -> Result<()> {
    let (expected, bump) = Pubkey::find_program_address(&[seed, wallet.as_ref()], &crate::ID);
    require_keys_eq!(credit.key(), expected, RouterError::WrongCreditAccount);
    let info = credit.to_account_info();
    if info.owner == &crate::ID {
        let c = Credit::try_deserialize(&mut &info.try_borrow_data()?[..])?;
        require_keys_eq!(c.wallet, wallet, RouterError::WrongCreditAccount);
        return Ok(());
    }
    let seeds: &[&[u8]] = &[seed, wallet.as_ref(), &[bump]];
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
fn add_credit_in(seed: &[u8], credit: &UncheckedAccount, wallet: Pubkey, amount: u64) -> Result<()> {
    let (expected, _) = Pubkey::find_program_address(&[seed, wallet.as_ref()], &crate::ID);
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
pub struct Credit {
    pub wallet: Pubkey,
    /// Lamports `wallet` can collect.
    pub amount: u64,
    pub bump: u8,
}

// ============================================================================ accounts and instruction contexts

#[account]
#[derive(InitSpace)]
pub struct ConfigV4 {
    pub owner: Pubkey,
    pub pending_owner: Pubkey,
    pub protocol_wallet: Pubkey,
    /// Fee floor, lamports. At most `max_min_fee`.
    pub min_fee: u64,
    /// Cap on the floor, lamports. Set once at `initialize_v4`; no setter.
    pub max_min_fee: u64,
    /// Fee rate, basis points of the SOL side; at most `MAX_FEE_BPS_V4`.
    pub fee_bps: u16,
    /// Payee share, basis points of the fee; at most `MAX_PAYEE_SHARE_BPS`.
    pub payee_share_bps: u16,
    /// The community's part of the payee share when a trade names both payees, basis points of the share.
    pub community_split_bps: u16,
    /// Sum of all V4 credits (protocol + payees); the V4 vault always holds exactly this above its rent reserve.
    pub total_credited: u64,
    pub bump: u8,
    pub vault_bump: u8,
}

/// A community (kind 1) or referral (kind 2), at PDA ["payee", id], id = the EVM `payeeId`.
#[account]
#[derive(InitSpace)]
pub struct Payee {
    pub kind: u8,
    /// The EVM address that signs its registrations.
    pub owner: [u8; 20],
    pub name: [u8; 32],
    /// Payout wallet on Solana.
    pub wallet: Pubkey,
    pub version: u64,
    /// Lamports it can collect.
    pub amount: u64,
    pub bump: u8,
}

/// The signed message (same fields and signature as on EVM) plus the signature itself.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Registration {
    pub kind: u8,
    pub owner: [u8; 20],
    pub name: [u8; 32],
    /// The EVM payout wallet: part of the signed message (unused on Solana).
    pub evm_wallet: [u8; 20],
    /// The Solana payout wallet; must not be empty here.
    pub solana_wallet: Pubkey,
    pub version: u64,
    /// r (32) | s (32) | v (1), v = 27 or 28.
    pub signature: [u8; 65],
}

/// A payee a trade names: its ID and the payout wallet the app expects it to have.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Party {
    pub id: [u8; 32],
    pub wallet: Pubkey,
}

#[derive(Accounts)]
pub struct InitializeV4<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + ConfigV4::INIT_SPACE, seeds = [CONFIG_V4_SEED], bump)]
    pub config: Account<'info, ConfigV4>,
    /// CHECK: lamport-only PDA (system-owned, no data); its address is fixed by the seeds.
    #[account(mut, seeds = [VAULT_V4_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the protocol wallet's V4 credit PDA; address checked and account created in `ensure_credit_in`.
    #[account(mut)]
    pub protocol_credit: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ RouterError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::AlphabrosRouter>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ RouterError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ConfigV4OwnerOnly<'info> {
    pub owner: Signer<'info>,
    #[account(mut, seeds = [CONFIG_V4_SEED], bump = config.bump, has_one = owner @ RouterError::NotOwner)]
    pub config: Account<'info, ConfigV4>,
}

#[derive(Accounts)]
pub struct SetProtocolWalletV4<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut, seeds = [CONFIG_V4_SEED], bump = config.bump, has_one = owner @ RouterError::NotOwner)]
    pub config: Account<'info, ConfigV4>,
    /// CHECK: lamport-only PDA; only its address is used.
    #[account(seeds = [VAULT_V4_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the new wallet's V4 credit PDA; address checked and account created in `ensure_credit_in`.
    #[account(mut)]
    pub wallet_credit: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptOwnershipV4<'info> {
    pub new_owner: Signer<'info>,
    #[account(mut, seeds = [CONFIG_V4_SEED], bump = config.bump, constraint = config.pending_owner == new_owner.key() @ RouterError::NotPendingOwner)]
    pub config: Account<'info, ConfigV4>,
}

#[derive(Accounts)]
pub struct RegisterPayee<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: the payee PDA ["payee", id]; address checked and account created or updated in `register_payee`.
    #[account(mut)]
    pub payee: UncheckedAccount<'info>,
    /// CHECK: the V4 vault (only its address is used: it can never be a payout wallet).
    #[account(seeds = [VAULT_V4_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecuteV4<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [CONFIG_V4_SEED], bump = config.bump)]
    pub config: Box<Account<'info, ConfigV4>>,
    /// CHECK: lamport-only PDA, address fixed by the seeds.
    #[account(mut, seeds = [VAULT_V4_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the protocol wallet's V4 credit PDA; checked in `add_credit_in`.
    #[account(mut)]
    pub protocol_credit: UncheckedAccount<'info>,
    /// CHECK: the named community's payee PDA, checked in `resolve_payee` (none: no community).
    #[account(mut)]
    pub community_payee: Option<UncheckedAccount<'info>>,
    /// CHECK: the named referral's payee PDA, checked in `resolve_payee` (none: no referral).
    #[account(mut)]
    pub referral_payee: Option<UncheckedAccount<'info>>,
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
pub struct CollectPayee<'info> {
    #[account(mut, seeds = [CONFIG_V4_SEED], bump = config.bump)]
    pub config: Account<'info, ConfigV4>,
    /// CHECK: lamport-only PDA, address fixed by the seeds.
    #[account(mut, seeds = [VAULT_V4_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [PAYEE_SEED, &payee_id(payee.kind, &payee.owner, &payee.name)], bump = payee.bump, constraint = payee.wallet == wallet.key() @ RouterError::WrongCreditAccount)]
    pub payee: Account<'info, Payee>,
    /// CHECK: receives the lamports; must be the payee's current wallet (checked on `payee`).
    #[account(mut)]
    pub wallet: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CollectV4<'info> {
    #[account(mut, seeds = [CONFIG_V4_SEED], bump = config.bump)]
    pub config: Account<'info, ConfigV4>,
    /// CHECK: lamport-only PDA, address fixed by the seeds.
    #[account(mut, seeds = [VAULT_V4_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [CREDIT_V4_SEED, wallet.key().as_ref()], bump = credit.bump, constraint = credit.wallet == wallet.key() @ RouterError::WrongCreditAccount)]
    pub credit: Account<'info, Credit>,
    /// CHECK: receives the lamports; must be the credit's wallet (checked on `credit`).
    #[account(mut)]
    pub wallet: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ============================================================================ events

/// One per V4 swap: who traded, which community and referral it named, where their shares were credited, and the
/// split. An ID is zero when the trade named none; a wallet is the default key (and its fee 0) when that payee earned
/// nothing. fee = protocol_fee + community_fee + referral_fee.
#[event]
pub struct FeePaid {
    pub user: Pubkey,
    pub community_id: [u8; 32],
    pub referral_id: [u8; 32],
    pub community_wallet: Pubkey,
    pub referral_wallet: Pubkey,
    pub fee: u64,
    pub protocol_fee: u64,
    pub community_fee: u64,
    pub referral_fee: u64,
    pub input_mint: Pubkey,
    pub output_mint: Pubkey,
    pub spent: u64,
    pub received: u64,
}

#[event]
pub struct PayeeRegistered {
    pub id: [u8; 32],
    pub kind: u8,
    pub owner: [u8; 20],
    pub name: [u8; 32],
    pub wallet: Pubkey,
    pub version: u64,
}

/// The V4 settings after any change (and at initialize).
#[event]
pub struct V4Settings {
    pub owner: Pubkey,
    pub protocol_wallet: Pubkey,
    pub min_fee: u64,
    pub fee_bps: u16,
    pub payee_share_bps: u16,
    pub community_split_bps: u16,
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
    #[msg("The payee is not registered as that kind, or its stored wallet is not the one the trade expects")]
    PayeeMismatch,
    #[msg("Registration fields are invalid")]
    BadRegistration,
    #[msg("The registration signature is not the owner's")]
    BadSignature,
    #[msg("The swap was handed a writable mint naming the user as an authority, or another account of a mint through which the user can act on accounts it does not own")]
    AuthorityExposed,
}
