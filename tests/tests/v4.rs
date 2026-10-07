//! Alphabros V4 on Solana — LiteSVM tests against the compiled program (target/deploy/*.so).
//!
//! One config (`config_v4`): a fee rate the owner sets (at most 0.5%) and one payee share (at most 60% of the fee) that
//! goes whole to the community OR the referral a trade names, split when it names both. Communities and referrals
//! register with the SAME EIP-712 signature as on the EVM router (owner's secp256k1 key, no chain ID): the parity test
//! signs the digest the live EVM contract returned and the program must accept it.
use alphabros_router::{self as router, ConfigV4, Credit, Party, Payee, Registration, RouterError};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use k256::ecdsa::SigningKey;
use litesvm::LiteSVM;
use sha3::{Digest, Keccak256};
use solana_account::Account;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{Transaction, TransactionError};
use spl_token_interface::state::{Account as TokenAccount, AccountState, Mint};

const ROUTER_SO: &str = "../target/deploy/alphabros_router.so";
const MOCK_SO: &str = "../target/deploy/mock_swap.so";
const SOL: u64 = 1_000_000_000;
const MIN_FEE: u64 = 2_500_000;
const MAX_MIN_FEE: u64 = 50_000_000;

// Ground truth from the live EVM V4 router (Base, 0xF5502aa5…de90) for kind 1, owner = address of the public test key
// 0x0101…01, name "ALPHA", wallet 0x1111…11, solanaWallet 0x2222…22, version 1:
const EVM_DIGEST: &str = "bc7fb06e5544d625f50530f0e450d4c132c6736a3158eef5ac43d32669d05236";
const EVM_PAYEE_ID: &str = "e0e132801816bec40c2da140d5dbbed500f4dcc9eb7f87e3d19e1886612d37ee";
const TEST_OWNER: &str = "1a642f0e3c3af545e7acbd38b07251b3990914f1";

fn hex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}
fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}
fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn word(b: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[32 - b.len()..].copy_from_slice(b);
    w
}
/// Independent re-implementation of the EVM `registrationDigest` (the program has its own).
fn digest(r: &Registration) -> [u8; 32] {
    let typehash = keccak(&[b"Registration(uint8 kind,address owner,bytes32 name,address wallet,bytes32 solanaWallet,uint64 version)"]);
    let domain = keccak(&[
        &keccak(&[b"EIP712Domain(string name,string version,address verifyingContract)"]),
        &keccak(&[b"Alphabros"]),
        &keccak(&[b"4"]),
        &word(&hex("F5502aa596cDA6705EB3ADd95BcA44C7c367de90".to_lowercase().as_str())),
    ]);
    let sh = keccak(&[&typehash, &word(&[r.kind]), &word(&r.owner), &r.name, &word(&r.evm_wallet), r.solana_wallet.as_ref(), &word(&r.version.to_be_bytes())]);
    keccak(&[&[0x19, 0x01], &domain, &sh])
}
fn payee_id(kind: u8, owner: &[u8; 20], name: &[u8; 32]) -> [u8; 32] {
    keccak(&[&word(&[kind]), &word(owner), name])
}
fn eth_address(key: &SigningKey) -> [u8; 20] {
    let p = key.verifying_key().to_encoded_point(false);
    arr(&keccak(&[&p.as_bytes()[1..]])[12..])
}
fn name32(s: &str) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..s.len()].copy_from_slice(s.as_bytes());
    n
}
/// A registration signed by `key` (its owner is `key`'s address unless `owner` overrides it).
fn signed(key: &SigningKey, kind: u8, name: &str, wallet: Pubkey, version: u64, owner: Option<[u8; 20]>) -> Registration {
    let mut r = Registration {
        kind,
        owner: owner.unwrap_or_else(|| eth_address(key)),
        name: name32(name),
        evm_wallet: [0x11; 20],
        solana_wallet: wallet,
        version,
        signature: [0u8; 65],
    };
    let (sig, recid) = key.sign_prehash_recoverable(&digest(&r)).unwrap();
    r.signature[..64].copy_from_slice(&sig.to_bytes());
    r.signature[64] = 27 + recid.to_byte();
    r
}

fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}
fn config_v4() -> Pubkey {
    pda(&[router::CONFIG_V4_SEED], &router::ID)
}
fn vault_v4() -> Pubkey {
    pda(&[router::VAULT_V4_SEED], &router::ID)
}
fn credit_v4(wallet: &Pubkey) -> Pubkey {
    pda(&[router::CREDIT_V4_SEED, wallet.as_ref()], &router::ID)
}
fn payee_pda(id: &[u8; 32]) -> Pubkey {
    pda(&[router::PAYEE_SEED, id], &router::ID)
}
fn pool_authority() -> Pubkey {
    pda(&[mock_swap::POOL_SEED], &mock_swap::ID)
}
fn wsol() -> Pubkey {
    router::WSOL_MINT
}
fn token_program() -> Pubkey {
    spl_token_interface::ID
}
fn custom_code(err: &TransactionError) -> Option<u32> {
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
        _ => None,
    }
}
fn code(e: RouterError) -> u32 {
    6000 + e as u32
}
fn programdata_address(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID).0
}
fn set_upgrade_authority(svm: &mut LiteSVM, program: &Pubkey, authority: Pubkey) {
    let pd = programdata_address(program);
    let mut acc = svm.get_account(&pd).unwrap();
    acc.data[12] = 1;
    acc.data[13..45].copy_from_slice(authority.as_ref());
    svm.set_account(pd, acc).unwrap();
}

struct Env {
    svm: LiteSVM,
    admin: Keypair,
    protocol_wallet: Pubkey,
    user: Keypair,
    payer: Keypair,
    meme: Pubkey,
    pool_wsol: Pubkey,
    pool_meme: Pubkey,
    user_wsol: Pubkey,
    user_meme: Pubkey,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let admin = Keypair::new();
        svm.add_program_from_file(router::ID, ROUTER_SO).expect("build the router first");
        svm.add_program_from_file(mock_swap::ID, MOCK_SO).expect("build mock_swap first");
        set_upgrade_authority(&mut svm, &router::ID, admin.pubkey());
        let mut env = Env {
            svm,
            admin,
            protocol_wallet: Pubkey::new_unique(),
            user: Keypair::new(),
            payer: Keypair::new(),
            meme: Pubkey::new_unique(),
            pool_wsol: Pubkey::new_unique(),
            pool_meme: Pubkey::new_unique(),
            user_wsol: Pubkey::new_unique(),
            user_meme: Pubkey::new_unique(),
        };
        for kp in [&env.admin, &env.user, &env.payer] {
            env.svm.airdrop(&kp.pubkey(), 1_000 * SOL).unwrap();
        }
        env.mint(wsol(), 9);
        let meme = env.meme;
        env.mint(meme, 6);
        let pa = pool_authority();
        env.token_account(env.pool_wsol, wsol(), pa, 10_000 * SOL);
        env.token_account(env.pool_meme, meme, pa, 1_000_000_000_000);
        let u = env.user.pubkey();
        env.token_account(env.user_wsol, wsol(), u, 100 * SOL);
        env.token_account(env.user_meme, meme, u, 0);
        env.init(50, 6_000, 5_000).unwrap();
        env
    }

    fn mint(&mut self, address: Pubkey, decimals: u8) {
        let mut data = vec![0u8; Mint::LEN];
        Mint { mint_authority: COption::None, supply: 0, decimals, is_initialized: true, freeze_authority: COption::None }.pack_into_slice(&mut data);
        let lamports = self.svm.minimum_balance_for_rent_exemption(Mint::LEN);
        self.svm.set_account(address, Account { lamports, data, owner: token_program(), executable: false, rent_epoch: 0 }).unwrap();
    }

    fn token_account(&mut self, address: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
        let rent = self.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
        let native = mint == wsol();
        let mut data = vec![0u8; TokenAccount::LEN];
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: if native { COption::Some(rent) } else { COption::None },
            delegated_amount: 0,
            close_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        let lamports = if native { rent + amount } else { rent };
        self.svm.set_account(address, Account { lamports, data, owner: token_program(), executable: false, rent_epoch: 0 }).unwrap();
    }

    fn send(&mut self, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let msg = Message::new(ixs, Some(&payer.pubkey()));
        let mut all: Vec<&Keypair> = vec![payer];
        all.extend_from_slice(signers);
        let tx = Transaction::new(&all, msg, self.svm.latest_blockhash());
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn init_as(&mut self, payer: &Keypair, fee: u16, share: u16, split: u16) -> Result<(), TransactionError> {
        let ix = Instruction {
            program_id: router::ID,
            accounts: router::accounts::InitializeV4 {
                payer: payer.pubkey(),
                config: config_v4(),
                vault: vault_v4(),
                protocol_credit: credit_v4(&self.protocol_wallet),
                program: router::ID,
                program_data: programdata_address(&router::ID),
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: router::instruction::InitializeV4 {
                owner: self.admin.pubkey(),
                protocol_wallet: self.protocol_wallet,
                min_fee: MIN_FEE,
                max_min_fee: MAX_MIN_FEE,
                fee_bps: fee,
                payee_share_bps: share,
                community_split_bps: split,
            }
            .data(),
        };
        self.send(&[ix], payer, &[])
    }
    fn init(&mut self, fee: u16, share: u16, split: u16) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        self.init_as(&admin, fee, share, split)
    }

    fn config(&self) -> ConfigV4 {
        ConfigV4::try_deserialize(&mut &self.svm.get_account(&config_v4()).unwrap().data[..]).unwrap()
    }
    fn payee(&self, id: &[u8; 32]) -> Option<Payee> {
        let a = self.svm.get_account(&payee_pda(id))?;
        if a.owner != router::ID {
            return None;
        }
        Some(Payee::try_deserialize(&mut &a.data[..]).unwrap())
    }
    fn protocol_credit(&self) -> u64 {
        Credit::try_deserialize(&mut &self.svm.get_account(&credit_v4(&self.protocol_wallet)).unwrap().data[..]).unwrap().amount
    }
    fn lamports(&self, a: &Pubkey) -> u64 {
        self.svm.get_account(a).map(|x| x.lamports).unwrap_or(0)
    }

    fn register_ix(&self, reg: &Registration) -> Instruction {
        let id = payee_id(reg.kind, &reg.owner, &reg.name);
        Instruction {
            program_id: router::ID,
            accounts: router::accounts::RegisterPayee {
                payer: self.payer.pubkey(),
                payee: payee_pda(&id),
                vault: vault_v4(),
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: router::instruction::RegisterPayee { reg: reg.clone() }.data(),
        }
    }
    fn register(&mut self, reg: &Registration) -> Result<(), TransactionError> {
        let ix = self.register_ix(reg);
        let payer = self.payer.insecure_clone();
        self.send(&[ix], &payer, &[])
    }

    /// The mock venue: the user pays `sol_in` wSOL and gets `meme_out`.
    fn venue_buy(&self, sol_in: u64, meme_out: u64) -> Instruction {
        Instruction {
            program_id: mock_swap::ID,
            accounts: mock_swap::accounts::Swap {
                user: self.user.pubkey(),
                user_in: self.user_wsol,
                user_out: self.user_meme,
                pool_in: self.pool_wsol,
                pool_out: self.pool_meme,
                pool_authority: pool_authority(),
                mint_in: wsol(),
                mint_out: self.meme,
                token_program_in: token_program(),
                token_program_out: token_program(),
            }
            .to_account_metas(None),
            data: mock_swap::instruction::Swap { amount_in: sol_in, amount_out: meme_out }.data(),
        }
    }

    /// `execute_v4` for a buy of `sol_in` wSOL, naming `community` / `referral` (payee account + party).
    fn buy_ix(&self, sol_in: u64, max_fee: u64, community: Option<(Pubkey, Party)>, referral: Option<(Pubkey, Party)>) -> Instruction {
        let venue = self.venue_buy(sol_in, 1_000);
        let mut accounts = router::accounts::ExecuteV4 {
            user: self.user.pubkey(),
            config: config_v4(),
            vault: vault_v4(),
            protocol_credit: credit_v4(&self.protocol_wallet),
            community_payee: community.as_ref().map(|c| c.0),
            referral_payee: referral.as_ref().map(|r| r.0),
            input_account: self.user_wsol,
            output_account: self.user_meme,
            swap_program: venue.program_id,
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None);
        accounts.extend(venue.accounts.iter().cloned());
        Instruction {
            program_id: router::ID,
            accounts,
            data: router::instruction::ExecuteV4 {
                min_out: 1,
                max_fee,
                max_input: sol_in,
                max_wallet_spend: 0,
                deadline: i64::MAX,
                swap_data: venue.data,
                community: community.map(|c| c.1),
                referral: referral.map(|r| r.1),
            }
            .data(),
        }
    }
    fn buy(&mut self, sol_in: u64, community: Option<(Pubkey, Party)>, referral: Option<(Pubkey, Party)>) -> Result<(), TransactionError> {
        let ix = self.buy_ix(sol_in, SOL, community, referral);
        let user = self.user.insecure_clone();
        self.send(&[ix], &user, &[])
    }

    /// The vault holds exactly the V4 credits above its rent reserve; the credits add up.
    fn assert_solvent(&self, payee_ids: &[[u8; 32]]) {
        let cfg = self.config();
        let rent = self.svm.minimum_balance_for_rent_exemption(0);
        assert_eq!(self.lamports(&vault_v4()) - rent, cfg.total_credited, "vault holds exactly the credits");
        let payees: u64 = payee_ids.iter().map(|id| self.payee(id).map(|p| p.amount).unwrap_or(0)).sum();
        assert_eq!(self.protocol_credit() + payees, cfg.total_credited, "credits add up");
    }
}

fn party_of(reg: &Registration) -> (Pubkey, Party) {
    let id = payee_id(reg.kind, &reg.owner, &reg.name);
    (payee_pda(&id), Party { id, wallet: reg.solana_wallet })
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32].into()).unwrap()
}
fn pct(amount: u64, bps: u64) -> u64 {
    ((amount as u128 * bps as u128 + 9_999) / 10_000) as u64
}

// ================================================================================ EVM parity

/// The digest and ID match the live EVM router, and the program accepts the signature of the EVM digest: one
/// signature serves EVM and Solana.
#[test]
fn evm_signature_registers_on_solana() {
    let mut env = Env::new();
    let k = key(1);
    assert_eq!(hex(TEST_OWNER).as_slice(), eth_address(&k).as_slice(), "test key -> the EVM test owner");
    let reg = signed(&k, 1, "ALPHA", Pubkey::new_from_array([0x22; 32]), 1, None);
    assert_eq!(digest(&reg).to_vec(), hex(EVM_DIGEST), "same EIP-712 digest as the EVM router");
    let id = payee_id(1, &reg.owner, &reg.name);
    assert_eq!(id.to_vec(), hex(EVM_PAYEE_ID), "same payee ID as the EVM router");
    env.register(&reg).unwrap();
    let p = env.payee(&id).expect("payee stored");
    assert_eq!((p.kind, p.wallet, p.version, p.owner), (1, Pubkey::new_from_array([0x22; 32]), 1, reg.owner));
}

// ================================================================================ registration

#[test]
fn nobody_can_register_someone_elses_payee() {
    let mut env = Env::new();
    let owner = key(1);
    let squatter = key(2);
    // The squatter signs the owner's registration: refused.
    let fake = signed(&squatter, 1, "ALPHA", Pubkey::new_unique(), 1, Some(eth_address(&owner)));
    assert_eq!(custom_code(&env.register(&fake).unwrap_err()), Some(code(RouterError::BadSignature)));
    // The squatter's own "ALPHA" is a different ID.
    let own = signed(&squatter, 1, "ALPHA", Pubkey::new_unique(), 1, None);
    let real = signed(&owner, 1, "ALPHA", Pubkey::new_unique(), 1, None);
    assert_ne!(party_of(&own).1.id, party_of(&real).1.id);
    env.register(&own).unwrap();
    env.register(&real).unwrap();
    assert_eq!(env.payee(&party_of(&real).1.id).unwrap().wallet, real.solana_wallet);
}

#[test]
fn bad_signatures_and_fields_refused() {
    let mut env = Env::new();
    let k = key(3);
    let good = signed(&k, 2, "ref", Pubkey::new_unique(), 1, None);
    // high-s twin of the same signature
    let n = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let mut hs = good.clone();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = n[i] as i16 - good.signature[32 + i] as i16 - borrow;
        hs.signature[32 + i] = d.rem_euclid(256) as u8;
        borrow = if d < 0 { 1 } else { 0 };
    }
    hs.signature[64] = if good.signature[64] == 27 { 28 } else { 27 };
    assert_eq!(custom_code(&env.register(&hs).unwrap_err()), Some(code(RouterError::BadSignature)), "high s");
    let mut bad_v = good.clone();
    bad_v.signature[64] = 29;
    assert_eq!(custom_code(&env.register(&bad_v).unwrap_err()), Some(code(RouterError::BadSignature)), "v 29");
    let mut tampered = good.clone();
    tampered.solana_wallet = Pubkey::new_unique(); // not what was signed
    assert_eq!(custom_code(&env.register(&tampered).unwrap_err()), Some(code(RouterError::BadSignature)), "wallet swapped");
    let empty = signed(&k, 2, "ref", Pubkey::default(), 1, None);
    assert_eq!(custom_code(&env.register(&empty).unwrap_err()), Some(code(RouterError::BadRegistration)), "no Solana wallet");
    let v0 = signed(&k, 2, "ref", Pubkey::new_unique(), 0, None);
    assert_eq!(custom_code(&env.register(&v0).unwrap_err()), Some(code(RouterError::BadRegistration)), "version 0");
    let kind3 = signed(&k, 3, "ref", Pubkey::new_unique(), 1, None);
    assert_eq!(custom_code(&env.register(&kind3).unwrap_err()), Some(code(RouterError::BadRegistration)), "kind 3");
    env.register(&good).unwrap();
}

#[test]
fn higher_version_moves_the_wallet_older_never_returns() {
    let mut env = Env::new();
    let k = key(4);
    let (w1, w2) = (Pubkey::new_unique(), Pubkey::new_unique());
    let v1 = signed(&k, 1, "ALPHA", w1, 1, None);
    let v2 = signed(&k, 1, "ALPHA", w2, 2, None);
    let id = party_of(&v1).1.id;
    env.register(&v1).unwrap();
    env.register(&v2).unwrap();
    assert_eq!(env.payee(&id).unwrap().wallet, w2);
    env.register(&v1).unwrap(); // replay: no effect
    let p = env.payee(&id).unwrap();
    assert_eq!((p.wallet, p.version), (w2, 2));
}

// ================================================================================ swaps and the payee share

#[test]
fn community_only_takes_the_whole_share() {
    let mut env = Env::new();
    let reg = signed(&key(5), 1, "ALPHA", Pubkey::new_unique(), 1, None);
    env.register(&reg).unwrap();
    let c = party_of(&reg);
    let id = c.1.id;
    env.buy(10 * SOL, Some(c), None).unwrap();
    let fee = pct(10 * SOL, 50); // 0.5% of 10 SOL = 0.05 SOL
    let share = fee * 6_000 / 10_000;
    assert_eq!(env.payee(&id).unwrap().amount, share, "community: the whole 60%");
    assert_eq!(env.protocol_credit(), fee - share, "protocol: 40%");
    env.assert_solvent(&[id]);
}

#[test]
fn both_named_split_the_share() {
    let mut env = Env::new();
    let creg = signed(&key(6), 1, "ALPHA", Pubkey::new_unique(), 1, None);
    let rreg = signed(&key(7), 2, "bob", Pubkey::new_unique(), 1, None);
    env.register(&creg).unwrap();
    env.register(&rreg).unwrap();
    let (c, r) = (party_of(&creg), party_of(&rreg));
    let (cid, rid) = (c.1.id, r.1.id);
    env.buy(10 * SOL, Some(c), Some(r)).unwrap();
    let fee = pct(10 * SOL, 50);
    let pool = fee * 6_000 / 10_000;
    assert_eq!(env.payee(&cid).unwrap().amount, pool * 5_000 / 10_000, "community half");
    assert_eq!(env.payee(&rid).unwrap().amount, pool - pool * 5_000 / 10_000, "referral half");
    assert_eq!(env.protocol_credit(), fee - pool);
    env.assert_solvent(&[cid, rid]);
}

#[test]
fn unexpected_wallet_kind_or_unregistered_reverts() {
    let mut env = Env::new();
    let creg = signed(&key(8), 1, "ALPHA", Pubkey::new_unique(), 1, None);
    let rreg = signed(&key(8), 2, "ALPHA", Pubkey::new_unique(), 1, None);
    env.register(&creg).unwrap();
    env.register(&rreg).unwrap();
    let w0 = env.svm.get_account(&env.user_wsol).unwrap().lamports;
    // expected wallet differs
    let mut wrong = party_of(&creg);
    wrong.1.wallet = Pubkey::new_unique();
    assert_eq!(custom_code(&env.buy(SOL, Some(wrong), None).unwrap_err()), Some(code(RouterError::PayeeMismatch)), "wrong wallet");
    // a referral passed as the community
    assert_eq!(custom_code(&env.buy(SOL, Some(party_of(&rreg)), None).unwrap_err()), Some(code(RouterError::PayeeMismatch)), "wrong kind");
    // not registered
    let ghost = signed(&key(9), 1, "GHOST", Pubkey::new_unique(), 1, None);
    assert_eq!(custom_code(&env.buy(SOL, Some(party_of(&ghost)), None).unwrap_err()), Some(code(RouterError::PayeeMismatch)), "unregistered");
    // the account of another payee under a party's ID
    let mut swapped = party_of(&creg);
    swapped.0 = party_of(&rreg).0;
    assert_eq!(custom_code(&env.buy(SOL, Some(swapped), None).unwrap_err()), Some(code(RouterError::PayeeMismatch)), "other account");
    assert_eq!(env.svm.get_account(&env.user_wsol).unwrap().lamports, w0, "nothing moved");
}

#[test]
fn self_payee_earns_nothing_and_does_not_halve_the_other() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let mine = signed(&key(10), 1, "MINE", u, 1, None);
    let rreg = signed(&key(11), 2, "bob", Pubkey::new_unique(), 1, None);
    env.register(&mine).unwrap();
    env.register(&rreg).unwrap();
    let (m, r) = (party_of(&mine), party_of(&rreg));
    let (mid, rid) = (m.1.id, r.1.id);
    env.buy(10 * SOL, Some(m), Some(r)).unwrap();
    let fee = pct(10 * SOL, 50);
    assert_eq!(env.payee(&mid).unwrap().amount, 0, "the trader's own community earns nothing");
    assert_eq!(env.payee(&rid).unwrap().amount, fee * 6_000 / 10_000, "the referral gets the whole share");
    env.assert_solvent(&[mid, rid]);
}

#[test]
fn neither_named_all_to_protocol_and_fee_cap() {
    let mut env = Env::new();
    env.buy(10 * SOL, None, None).unwrap();
    assert_eq!(env.protocol_credit(), pct(10 * SOL, 50));
    // a small trade pays the floor
    env.buy(SOL / 10, None, None).unwrap();
    assert_eq!(env.protocol_credit(), pct(10 * SOL, 50) + MIN_FEE);
    // max_fee below the exact fee reverts
    let ix = env.buy_ix(10 * SOL, pct(10 * SOL, 50) - 1, None, None);
    let user = env.user.insecure_clone();
    assert_eq!(custom_code(&env.send(&[ix], &user, &[]).unwrap_err()), Some(code(RouterError::FeeTooLow)));
    env.assert_solvent(&[]);
}

// ================================================================================ owner settings

#[test]
fn initialize_only_by_upgrade_authority_and_caps() {
    let mut env = Env::new();
    // already initialized
    assert!(env.init(50, 6_000, 5_000).is_err());
    let mut fresh = Env { svm: LiteSVM::new(), ..Env::new() };
    fresh.svm.add_program_from_file(router::ID, ROUTER_SO).unwrap();
    let admin = fresh.admin.pubkey();
    set_upgrade_authority(&mut fresh.svm, &router::ID, admin);
    fresh.svm.airdrop(&fresh.admin.pubkey(), 10 * SOL).unwrap();
    let stranger = Keypair::new();
    fresh.svm.airdrop(&stranger.pubkey(), 10 * SOL).unwrap();
    assert_eq!(custom_code(&fresh.init_as(&stranger, 50, 6_000, 5_000).unwrap_err()), Some(code(RouterError::NotUpgradeAuthority)));
    assert_eq!(custom_code(&fresh.init(51, 6_000, 5_000).unwrap_err()), Some(code(RouterError::AboveCap)), "fee above 0.5%");
    assert_eq!(custom_code(&fresh.init(50, 6_001, 5_000).unwrap_err()), Some(code(RouterError::AboveCap)), "share above 60%");
    assert_eq!(custom_code(&fresh.init(50, 6_000, 10_001).unwrap_err()), Some(code(RouterError::AboveCap)), "split above 100%");
    fresh.init(30, 6_000, 5_000).unwrap();
    assert_eq!(fresh.config().fee_bps, 30);
}

#[test]
fn owner_changes_rate_and_shares_within_caps() {
    let mut env = Env::new();
    let owner_only = |owner: Pubkey, data: Vec<u8>| Instruction {
        program_id: router::ID,
        accounts: router::accounts::ConfigV4OwnerOnly { owner, config: config_v4() }.to_account_metas(None),
        data,
    };
    let admin = env.admin.insecure_clone();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let ix = owner_only(stranger.pubkey(), router::instruction::SetFeeBpsV4 { fee_bps: 30 }.data());
    assert_eq!(custom_code(&env.send(&[ix], &stranger, &[]).unwrap_err()), Some(code(RouterError::NotOwner)));
    let ix = owner_only(admin.pubkey(), router::instruction::SetFeeBpsV4 { fee_bps: 51 }.data());
    assert_eq!(custom_code(&env.send(&[ix], &admin, &[]).unwrap_err()), Some(code(RouterError::AboveCap)));
    let ix = owner_only(admin.pubkey(), router::instruction::SetSharesV4 { payee_share_bps: 6_001, community_split_bps: 5_000 }.data());
    assert_eq!(custom_code(&env.send(&[ix], &admin, &[]).unwrap_err()), Some(code(RouterError::AboveCap)));
    let a = owner_only(admin.pubkey(), router::instruction::SetFeeBpsV4 { fee_bps: 30 }.data());
    let b = owner_only(admin.pubkey(), router::instruction::SetSharesV4 { payee_share_bps: 3_000, community_split_bps: 7_000 }.data());
    env.send(&[a, b], &admin, &[]).unwrap();
    let cfg = env.config();
    assert_eq!((cfg.fee_bps, cfg.payee_share_bps, cfg.community_split_bps), (30, 3_000, 7_000));
    env.buy(10 * SOL, None, None).unwrap();
    assert_eq!(env.protocol_credit(), pct(10 * SOL, 30), "the new 0.3% rate applies");
}

// ================================================================================ collect

#[test]
fn collect_pays_the_payee_and_the_protocol() {
    let mut env = Env::new();
    let reg = signed(&key(12), 1, "ALPHA", Pubkey::new_unique(), 1, None);
    env.register(&reg).unwrap();
    let c = party_of(&reg);
    let (pda_, id, wallet) = (c.0, c.1.id, reg.solana_wallet);
    env.buy(10 * SOL, Some(c), None).unwrap();
    let earned = env.payee(&id).unwrap().amount;
    let protocol = env.protocol_credit();
    let caller = env.payer.insecure_clone();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::CollectPayee { config: config_v4(), vault: vault_v4(), payee: pda_, wallet, system_program: solana_system_interface::program::ID }.to_account_metas(None),
        data: router::instruction::CollectPayee {}.data(),
    };
    env.send(&[ix], &caller, &[]).unwrap();
    assert_eq!(env.lamports(&wallet), earned, "the payee's wallet got what it earned");
    assert_eq!(env.payee(&id).unwrap().amount, 0);
    // a collect to any other wallet is refused
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::CollectPayee { config: config_v4(), vault: vault_v4(), payee: pda_, wallet: caller.pubkey(), system_program: solana_system_interface::program::ID }.to_account_metas(None),
        data: router::instruction::CollectPayee {}.data(),
    };
    assert!(env.send(&[ix], &caller, &[]).is_err());
    let pw = env.protocol_wallet;
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::CollectV4 { config: config_v4(), vault: vault_v4(), credit: credit_v4(&pw), wallet: pw, system_program: solana_system_interface::program::ID }.to_account_metas(None),
        data: router::instruction::CollectV4 {}.data(),
    };
    env.send(&[ix], &caller, &[]).unwrap();
    assert_eq!(env.lamports(&pw), protocol);
    assert_eq!(env.config().total_credited, 0);
    env.assert_solvent(&[id]);
}

/// Registration and the first trade in one transaction (lazy first use): the payer of the registration pays its rent,
/// the swap still charges the user exactly the fee.
#[test]
fn register_and_trade_in_one_transaction() {
    let mut env = Env::new();
    let reg = signed(&key(13), 2, "carol", Pubkey::new_unique(), 1, None);
    let r = party_of(&reg);
    let rid = r.1.id;
    let reg_ix = env.register_ix(&reg);
    let buy_ix = env.buy_ix(10 * SOL, SOL, None, Some(r));
    let user = env.user.insecure_clone();
    let payer = env.payer.insecure_clone();
    let u0 = env.lamports(&user.pubkey());
    env.send(&[reg_ix, buy_ix], &payer, &[&user]).unwrap();
    let fee = pct(10 * SOL, 50);
    assert_eq!(u0 - env.lamports(&user.pubkey()), fee, "the user paid exactly the fee (the payer paid fees and rent)");
    assert_eq!(env.payee(&rid).unwrap().amount, fee * 6_000 / 10_000);
    env.assert_solvent(&[rid]);
}
