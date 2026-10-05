//! Test-only swap venue. `swap` takes `amount_in` of the input token from the signing user and pays `amount_out` of
//! the output token from the pool (a PDA-owned token account) to `user_out`. The amounts are whatever the test asks
//! for, so tests can drive exact outputs, short fills and refunds. Never deployed outside tests.
use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Approve, Mint, TokenAccount, TokenInterface, TransferChecked};

declare_id!("Hte3qNH744tdMRdrajqyfakcLgwZmcj4iNTd28i75dAm");

pub const POOL_SEED: &[u8] = b"pool";

#[program]
pub mod mock_swap {
    use super::*;

    pub fn swap(ctx: Context<Swap>, amount_in: u64, amount_out: u64) -> Result<()> {
        if amount_in > 0 {
            token_interface::transfer_checked(
                CpiContext::new(
                    ctx.accounts.token_program_in.key(),
                    TransferChecked {
                        from: ctx.accounts.user_in.to_account_info(),
                        mint: ctx.accounts.mint_in.to_account_info(),
                        to: ctx.accounts.pool_in.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    },
                ),
                amount_in,
                ctx.accounts.mint_in.decimals,
            )?;
        }
        if amount_out > 0 {
            let bump = ctx.bumps.pool_authority;
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program_out.key(),
                    TransferChecked {
                        from: ctx.accounts.pool_out.to_account_info(),
                        mint: ctx.accounts.mint_out.to_account_info(),
                        to: ctx.accounts.user_out.to_account_info(),
                        authority: ctx.accounts.pool_authority.to_account_info(),
                    },
                    &[&[POOL_SEED, &[bump]]],
                ),
                amount_out,
                ctx.accounts.mint_out.decimals,
            )?;
        }
        Ok(())
    }

    /// Misbehaving venue for tests: swaps, then uses the user's signature to approve `delegate` on the user's input
    /// account. The router must refuse this.
    pub fn swap_and_approve<'info>(ctx: Context<'info, Swap<'info>>, amount_in: u64, amount_out: u64, delegate: Pubkey) -> Result<()> {
        let program = ctx.accounts.token_program_in.key();
        let user_in = ctx.accounts.user_in.to_account_info();
        let user = ctx.accounts.user.to_account_info();
        let delegate_info = ctx
            .remaining_accounts
            .iter()
            .find(|a| *a.key == delegate)
            .ok_or(error!(ErrorCode::AccountNotEnoughKeys))?
            .clone();
        swap(ctx, amount_in, amount_out)?;
        token_interface::approve(
            CpiContext::new(program, Approve { to: user_in, delegate: delegate_info, authority: user }),
            u64::MAX,
        )?;
        Ok(())
    }

    /// Bonding-curve venue for tests (Pump.fun style): trades the token against the user's WALLET SOL, not wSOL.
    /// Buy: takes `lamports_in` from the wallet and pays `amount_out` tokens. Sell: takes `amount_in` tokens and pays
    /// `lamports_out` from the curve (the pool PDA) to the wallet.
    pub fn curve(ctx: Context<Curve>, lamports_in: u64, amount_out: u64, amount_in: u64, lamports_out: u64) -> Result<()> {
        let bump = ctx.bumps.pool_authority;
        let seeds: &[&[&[u8]]] = &[&[POOL_SEED, &[bump]]];
        if lamports_in > 0 {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.user.to_account_info(),
                        to: ctx.accounts.pool_authority.to_account_info(),
                    },
                ),
                lamports_in,
            )?;
        }
        if amount_out > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.key(),
                    TransferChecked {
                        from: ctx.accounts.pool_token.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.user_token.to_account_info(),
                        authority: ctx.accounts.pool_authority.to_account_info(),
                    },
                    seeds,
                ),
                amount_out,
                ctx.accounts.mint.decimals,
            )?;
        }
        if amount_in > 0 {
            token_interface::transfer_checked(
                CpiContext::new(
                    ctx.accounts.token_program.key(),
                    TransferChecked {
                        from: ctx.accounts.user_token.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.pool_token.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    },
                ),
                amount_in,
                ctx.accounts.mint.decimals,
            )?;
        }
        if lamports_out > 0 {
            anchor_lang::system_program::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.pool_authority.to_account_info(),
                        to: ctx.accounts.user.to_account_info(),
                    },
                    seeds,
                ),
                lamports_out,
            )?;
        }
        Ok(())
    }

    /// Hostile venue doing several things in one swap: the remaining accounts are consecutive groups of a target
    /// program followed by `counts[i]` accounts, each called with `datas[i]` and every permission it was given.
    pub fn relay_many<'info>(ctx: Context<'info, Relay>, counts: Vec<u8>, datas: Vec<Vec<u8>>) -> Result<()> {
        let mut rest = ctx.remaining_accounts;
        for (count, data) in counts.iter().zip(datas) {
            let (target, tail) = rest.split_first().ok_or(error!(ErrorCode::AccountNotEnoughKeys))?;
            let (accounts, tail) = tail.split_at(*count as usize);
            let metas = accounts
                .iter()
                .map(|a| anchor_lang::solana_program::instruction::AccountMeta {
                    pubkey: *a.key,
                    is_signer: a.is_signer,
                    is_writable: a.is_writable,
                })
                .collect();
            let ix = anchor_lang::solana_program::instruction::Instruction { program_id: *target.key, accounts: metas, data };
            anchor_lang::solana_program::program::invoke(&ix, ctx.remaining_accounts)?;
            rest = tail;
        }
        Ok(())
    }

    /// Hostile venue for tests: calls `target` (the first remaining account) with `data` and the other remaining
    /// accounts, passing on every signature and write permission it was given. Whatever a venue could do with the
    /// user's signature, a test can make it do through this.
    pub fn relay<'info>(ctx: Context<'info, Relay>, data: Vec<u8>) -> Result<()> {
        let (target, rest) = ctx.remaining_accounts.split_first().ok_or(error!(ErrorCode::AccountNotEnoughKeys))?;
        let metas = rest
            .iter()
            .map(|a| anchor_lang::solana_program::instruction::AccountMeta {
                pubkey: *a.key,
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect();
        let ix = anchor_lang::solana_program::instruction::Instruction { program_id: *target.key, accounts: metas, data };
        anchor_lang::solana_program::program::invoke(&ix, ctx.remaining_accounts)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Relay {}

#[derive(Accounts)]
pub struct Curve<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub user_token: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub pool_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the pool's signing PDA, also the curve's SOL reserve.
    #[account(mut, seeds = [POOL_SEED], bump)]
    pub pool_authority: UncheckedAccount<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub user_in: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub user_out: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub pool_in: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub pool_out: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the pool's signing PDA.
    #[account(seeds = [POOL_SEED], bump)]
    pub pool_authority: UncheckedAccount<'info>,
    pub mint_in: InterfaceAccount<'info, Mint>,
    pub mint_out: InterfaceAccount<'info, Mint>,
    pub token_program_in: Interface<'info, TokenInterface>,
    pub token_program_out: Interface<'info, TokenInterface>,
}
