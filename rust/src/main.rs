#![allow(unused)]
use bitcoincore_rpc::bitcoin::address::NetworkUnchecked;
use bitcoincore_rpc::bitcoin::{Address, Amount, Network, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Write};
use std::path::Path;

// Node access params
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port
const RPC_USER: &str = "alice";
const RPC_PASS: &str = "password";

// You can use calls not provided in RPC lib API using the generic `call` function.
// An example of using the `send` RPC call, which doesn't have exposed API.
// You can also use serde_json `Deserialize` derivation to capture the returned json result.
fn send(rpc: &Client, addr: &str, amount: Amount) -> bitcoincore_rpc::Result<String> {
    // List unspent outputs and find one with sufficient value
    let utxos = rpc.list_unspent(None, None, None, None, None)?;

    // Find a UTXO that can cover the amount + fee buffer (1000 sats)
    let utxo = utxos
        .iter()
        .find(|u| u.amount >= amount + Amount::from_sat(1000))
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "No suitable UTXO found"))?;

    // Prepare arguments for the 'send' RPC call
    let args = [
        json!([{addr : amount.to_btc() }]), // recipient address
        json!(null),                        // conf target
        json!(null),                        // estimate mode
        json!(null),                        // fee rate in sats/vb
        json!({                             // Options object specifying inputs
            "inputs": [{
                "txid": utxo.txid.to_string(),
                "vout": utxo.vout
            }]
        }),
    ];

    #[derive(Deserialize)]
    struct SendResult {
        complete: bool,
        txid: String,
    }
    let send_result = rpc.call::<SendResult>("send", &args)?;
    assert!(send_result.complete);

    Ok(send_result.txid)
}

const MINER_WALLET: &str = "Miner";
const TRADER_WALLET: &str = "Trader";

// Transaction details saved in out.txt
#[derive(Debug)]
struct TransactionDetails {
    txid: String,
    miner_input_address: String,
    miner_input_amount: f64,
    trader_output_address: String,
    trader_output_amount: f64,
    miner_change_address: String,
    miner_change_amount: f64,
    tx_fees: u64,
    block_height: u64,
    block_hash: String,
}

fn main() -> bitcoincore_rpc::Result<()> {
    // Connect to Bitcoin Core RPC
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // Get blockchain info
    let blockchain_info = rpc.get_blockchain_info()?;
    println!("Blockchain Info: {:?}", blockchain_info);

    // Create/Load the wallets, named 'Miner' and 'Trader'. Have logic to optionally create/load them if they do not exist or not loaded already.
    println!("Creating wallets...");
    create_or_load_wallets(&rpc)?;

    // Generate address for Miner wallet
    println!("Generating miner address...");
    let miner_address = generate_miner_address(&rpc)?;
    println!("Miner address: {}", miner_address);

    // Parse the miner address string; not yet tied to any specific network
    let parsed_address: Address<NetworkUnchecked> =
        miner_address.parse().expect("Invalid Bitcoin address");

    // Verify that the parsed address belongs to the regtest network
    let miner_address = parsed_address
        .require_network(Network::Regtest)
        .expect("Address is not valid for regtest");

    // Generate spendable balances in the Miner wallet. How many blocks needs to be mined?
    // Mine until coinbase maturity (100 confirmations) gives spendable funds
    println!("Mining blocks until Miner has spendable balance...");
    let blocks_mined = mine_until_balance(&rpc, &miner_address)?;
    println!("Mined {} blocks to get positive balance", blocks_mined);

    // Print Miner wallet balance
    let miner_rpc = get_wallet_client(MINER_WALLET)?;
    let balance = miner_rpc.get_balance(None, None)?;
    println!("Miner wallet balance: {} BTC", balance.to_btc());

    // Explain coinbase maturity
    // Coinbase transactions require 100 confirmations before funds are spendable.
    // We mine enough blocks to surpass this maturity, ensuring Miner can spend rewards.

    // Load Trader wallet and generate a new address
    println!("Generating Trader address...");
    let trader_address = generate_trader_address(&rpc)?;
    println!("Trader address: {}", trader_address);

    // Send 20 BTC from Miner to Trader
    println!("Sending 20 BTC from Miner to Trader...");
    let miner_rpc = get_wallet_client(MINER_WALLET)?;
    let amount = Amount::from_btc(20.0)?;
    let txid = send(&miner_rpc, &trader_address, amount)?;
    println!("20 BTC sent to Trader, txid: {}", txid);

    // Check transaction in mempool
    let txid_parsed: Txid = txid.parse().expect("Invalid txid");

// Check transaction in mempool
let mempool_entry = rpc.get_mempool_entry(&txid_parsed)
    .expect("Failed to get mempool entry");

println!("Transaction in Mempool: {:?}", mempool_entry);
    // Mine 1 block to confirm the transaction
    println!("Mining block to confirm transaction...");
    let block_hashes = rpc.generate_to_address(1, &miner_address)?;
    println!("Mined block: {:?}", block_hashes);
    let block_hash = &block_hashes[0];

    // Get current block height
    let block_height = rpc.get_block_count()?;
    // Extract all required transaction details
    let tx_details =
        extract_transaction_details(&rpc, &txid, &trader_address, block_height, block_hash)?;

    // Write the data to ../out.txt in the specified format given in readme.md
    write_transaction_data(&tx_details)?;
    println!("Transaction details written to out.txt");
    Ok(())
}

// Extract transaction data: input (miner), output (trader), change, fees
fn extract_transaction_details(
    rpc: &Client,
    txid: &str,
    trader_address: &str,
    block_height: u64,
    block_hash: &bitcoincore_rpc::bitcoin::BlockHash,
) -> bitcoincore_rpc::Result<TransactionDetails> {
    // Parse txid string to proper type
    let txid_hash: bitcoincore_rpc::bitcoin::Txid = txid
        .parse()
        .map_err(|_| IoError::new(ErrorKind::InvalidData, "Invalid txid"))?;

    // Get the raw transaction
    let tx_result = rpc.get_raw_transaction(&txid_hash, None)?;
    let tx = tx_result;

    // Get transaction details with verbose info
    let tx_details = rpc.get_raw_transaction_info(&txid_hash, None)?;

    // Extract miner input details (from the spent UTXO)
    let (miner_input_address, miner_input_amount) = get_miner_input(rpc, &tx_details)?;

    // Extract trader output (the 20 BTC sent to trader)
    let (trader_output_address, trader_output_amount) = get_trader_output(&tx, trader_address)?;

    // Extract miner change output
    let (miner_change_address, miner_change_amount) = get_miner_change(&tx, &trader_address)?;

    // Calculate transaction fee (inputs - outputs)
    let miner_input_sats = (miner_input_amount * 100_000_000.0).round() as u64;
    let trader_output_sats = (trader_output_amount * 100_000_000.0).round() as u64;
    let miner_change_sats = (miner_change_amount * 100_000_000.0).round() as u64;

    let tx_fees = miner_input_sats
        .saturating_sub(trader_output_sats)
        .saturating_sub(miner_change_sats);

    Ok(TransactionDetails {
        txid: txid.to_string(),
        miner_input_address,
        miner_input_amount,
        trader_output_address,
        trader_output_amount,
        miner_change_address,
        miner_change_amount,
        tx_fees,
        block_height,
        block_hash: block_hash.to_string(),
    })
}

// Write transaction details to `../out.txt`
fn write_transaction_data(details: &TransactionDetails) -> Result<(), IoError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("out.txt");

    let mut file = File::create(path)?;

    writeln!(file, "{}", details.txid)?;
    writeln!(file, "{}", details.miner_input_address)?;
    writeln!(file, "{}", details.miner_input_amount)?;
    writeln!(file, "{}", details.trader_output_address)?;
    writeln!(file, "{}", details.trader_output_amount)?;
    writeln!(file, "{}", details.miner_change_address)?;
    writeln!(file, "{}", details.miner_change_amount)?;
    writeln!(file, "{}", details.tx_fees as f64 / 100_000_000.0)?;
    writeln!(file, "{}", details.block_height)?;
    writeln!(file, "{}", details.block_hash)?;

    Ok(())
}

// Find miner input by inspecting previous transaction output
fn get_miner_input(
    rpc: &Client,
    tx: &bitcoincore_rpc::json::GetRawTransactionResult,
) -> bitcoincore_rpc::Result<(String, f64)> {
    // Get the first input
    let input = tx
        .vin
        .first()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "No inputs found"))?;

    // Get the previous transaction that created the input
    let prev_txid = input
        .txid
        .as_ref()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "No txid in input"))?;
    let prev_tx = rpc.get_raw_transaction(prev_txid, None)?;

    // Get the specific output being spent
    let vout = input
        .vout
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "No vout in input"))?;
    let prev_output = prev_tx.output.get(vout as usize).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("Invalid vout index {}", vout),
        )
    })?;

    // Get the address from output script
    let script = &prev_output.script_pubkey;
    let address = Address::from_script(script, Network::Regtest)
        .map_err(|_| {
            IoError::new(
                ErrorKind::InvalidData,
                "Unable to extract address from script",
            )
        })?
        .to_string();
    Ok((address, prev_output.value.to_btc()))
}

// Mine until wallet has matured coinbase funds (100 blocks)
fn mine_until_balance(rpc: &Client, miner_address: &Address) -> bitcoincore_rpc::Result<u64> {
    let miner_rpc = get_wallet_client(MINER_WALLET)?;
    
    // Mine 101 blocks to ensure coinbase maturity
    println!("Mining 101 blocks to ensure coinbase maturity...");
    rpc.generate_to_address(101, miner_address)?;
    
    let balance = miner_rpc.get_balance(None, None)?;
    println!("Miner balance after mining: {} BTC", balance.to_btc());
    
    Ok(101) // Return number of blocks mined
}

// Locate trader's output in transaction
fn get_trader_output(
    tx: &Transaction,
    trader_address: &str,
) -> bitcoincore_rpc::Result<(String, f64)> {
    for output in &tx.output {
        if let Ok(address) = Address::from_script(&output.script_pubkey, Network::Regtest) {
            if address.to_string() == trader_address {
                return Ok((address.to_string(), output.value.to_btc()));
            }
        }
    }
    Err(IoError::new(ErrorKind::InvalidData, "Trader output not found").into())
}

// Locate miner's change output
fn get_miner_change(tx: &Transaction, trader_address: &str) -> bitcoincore_rpc::Result<(String, f64)> {
    for output in &tx.output {
        if let Ok(address) = Address::from_script(&output.script_pubkey, Network::Regtest) {
            if address.to_string() != trader_address {
                return Ok((address.to_string(), output.value.to_btc()));
            }
        }
    }
    Err(IoError::new(ErrorKind::InvalidData, "No change output found").into())
}

// Create wallet if missing, otherwise load it
fn create_or_load_wallets(rpc: &Client) -> bitcoincore_rpc::Result<()> {
    create_or_load_wallet(rpc, MINER_WALLET);
    create_or_load_wallet(rpc, TRADER_WALLET);
    Ok(())
}

fn create_or_load_wallet(rpc: &Client, wallet_name: &str) -> bitcoincore_rpc::Result<()> {
    match rpc.create_wallet(wallet_name, None, None, None, None) {
        Ok(_) => println!("{} wallet created successfully", wallet_name),
        Err(e) => {
            if e.to_string().contains("Already exist") {
                println!("{} wallet already exists, loading it", wallet_name);
            }
            match rpc.load_wallet(wallet_name) {
                Ok(_) => println!("{} wallet loaded successfully", wallet_name),
                Err(e) => {
                    if e.to_string().contains("already loaded") {
                        println!("{} wallet already loaded", wallet_name)
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(())
}

// Return RPC client for a specific wallet
fn get_wallet_client(wallet_name: &str) -> bitcoincore_rpc::Result<Client> {
    Client::new(
        &format!("{}/wallet/{}", RPC_URL, wallet_name),
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )
}

// Generate address for mining rewards
fn generate_miner_address(rpc: &Client) -> bitcoincore_rpc::Result<String> {
    let miner_rpc = get_wallet_client(MINER_WALLET)?;
    let address = miner_rpc.get_new_address(Some("Mining Reward"), None)?;
    let checked_address = address
        .require_network(Network::Regtest)
        .expect("Address is not valid for regtest");
    Ok(checked_address.to_string())
}

// Generate address for trader wallet
fn generate_trader_address(rpc: &Client) -> bitcoincore_rpc::Result<String> {
    let trader_rpc = get_wallet_client(TRADER_WALLET)?;
    let address = trader_rpc.get_new_address(Some("Received"), None)?;
    let checked_address = address
        .require_network(Network::Regtest)
        .expect("Address is not valid for regtest");
    Ok(checked_address.to_string())
}
