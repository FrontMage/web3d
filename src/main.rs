#[macro_use]
extern crate rocket;
use anyhow::Result;
use bounded_vec_deque::BoundedVecDeque;
use docker_runner::{Docker, DockerRunner};
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::{TxHash, Wallet, U256};
use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use hex::FromHex;
use hex_literal::hex;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::response::status::BadRequest;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::State;
use rocket::{Request, Response};
use secp256k1::SecretKey;
use simplelog::*;
use std::default::Default;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::sync::{Arc, RwLock};
use tokio::join;
use web3::api::Eth;
use web3::contract::{Contract, Options};
use web3::transports::Http;
use web3::types::Address;
use web3::{
    ethabi::{self, param_type::ParamType, Token},
    futures::TryFutureExt,
    types::{BlockNumber, FilterBuilder},
};

const WEB3D_CONTAINER_TASK_ID_KEY: &'static str = "web3d_task_id";
const WEB3D_CONTAINER_DEADLINE_KEY: &'static str = "web3d_deadline";
const WEB3D_MAX_RUNNING_CONTAINER_COUNT: usize = 3;

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[get("/ping")]
fn ping() -> String {
    log::info!("ping");
    "pong".to_string()
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
struct EthAddressRes {
    eth_address: String,
}

#[get("/eth_address")]
fn get_eth_address(eth_address: &State<String>) -> Json<EthAddressRes> {
    Json(EthAddressRes {
        eth_address: eth_address.to_string(),
    })
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
struct WorkProofRes {
    work_proof: u64,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
struct RaceRes {
    success: bool,
    error: Option<String>,
}

/// Race task by task id
#[get("/complete?<task_id>")]
async fn complete_task(
    eth: &State<Eth<Http>>,
    eth_wallet: &State<Wallet<SigningKey>>,
    task_id: u64,
) -> Result<Json<RaceRes>, BadRequest<String>> {
    match call_contract(
        "completeSubIndexForTask",
        eth.inner().clone(),
        U256::from(task_id),
        eth_wallet.inner().clone(),
    )
    .await
    {
        Ok(_) => Ok(Json(RaceRes {
            success: true,
            error: None,
        })),
        Err(e) => Ok(Json(RaceRes {
            success: false,
            error: Some(format!("{:?}", e)),
        })),
    }
}

/// Race task by task id
#[get("/race?<task_id>")]
async fn race_for_task(
    eth: &State<Eth<Http>>,
    eth_wallet: &State<Wallet<SigningKey>>,
    task_id: u64,
) -> Result<Json<RaceRes>, BadRequest<String>> {
    match try_race_task(eth.inner().clone(), U256::from(task_id), &eth_wallet).await {
        Ok(_) => Ok(Json(RaceRes {
            success: true,
            error: None,
        })),
        Err(e) => Ok(Json(RaceRes {
            success: false,
            error: Some(format!("{:?}", e)),
        })),
    }
}

async fn is_task_raceable(
    eth: Eth<Http>,
    eth_wallet: &Wallet<SigningKey>,
    task_id: u64,
) -> Result<bool> {
    let contract = contract(eth.clone())?;
    let result: (U256, U256, U256, U256, U256, U256, U256, Address) = contract
        .query(
            "taskInfo",
            (U256::from(task_id),),
            eth_wallet.address(),
            Options {
                gas: Some(140850_u64.into()),
                ..Options::default()
            },
            None,
        )
        .await?;
    Ok(result.0 < result.1)
}

async fn query_work_proof(eth: Eth<Http>, eth_wallet: &Wallet<SigningKey>) -> Result<u64> {
    let contract = contract(eth.clone())?;
    let current_day: u64 = contract
        .query(
            "getCurrentDay",
            (),
            eth_wallet.address(),
            Options {
                gas: Some(140850_u64.into()),
                ..Options::default()
            },
            None,
        )
        .await?;
    let work_proof: u64 = contract
        .query(
            "getUserRewardForDay",
            (eth_wallet.address(), current_day),
            eth_wallet.address(),
            Options {
                gas: Some(140850_u64.into()),
                ..Options::default()
            },
            None,
        )
        .await?;
    Ok(work_proof)
}

#[get("/work_proof")]
async fn get_work_proof(
    eth: &State<Eth<Http>>,
    eth_wallet: &State<Wallet<SigningKey>>,
) -> Json<WorkProofRes> {
    match query_work_proof(eth.inner().clone(), &eth_wallet).await {
        Ok(work_proof) => Json(WorkProofRes {
            work_proof,
            error: None,
        }),
        Err(e) => Json(WorkProofRes {
            work_proof: 0_u64,
            error: Some(format!("{:?}", e)),
        }),
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(crate = "rocket::serde")]
struct TaskInfo {
    task_id: u64,
    image_url: String,
    args: String,
    max_run_num: u64,
    deadline: u64,
}

#[get("/tasks")]
async fn get_tasks(
    task_deque: &State<Arc<RwLock<BoundedVecDeque<TaskInfo>>>>,
) -> Json<Vec<TaskInfo>> {
    Json(
        task_deque
            .read()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<TaskInfo>>(),
    )
}

fn is_testnet() -> Result<bool, std::io::Error> {
    let f = OpenOptions::new().read(true).open("./chain.ini")?;
    for line in std::io::BufReader::new(f).lines() {
        let l = line?;
        if l.contains("TESTNET=") {
            return Ok(l.contains("TESTNET=\"yes\""));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "No TESTNET= filed in given file",
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        simplelog::Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .expect("Failed to init logger");
    match is_testnet() {
        Ok(is_running_on_testnet) => {
            log::info!("Is testnet: {}", is_running_on_testnet);
            let wallet = if is_running_on_testnet {
                "./key/eth.keystore.testnet"
            } else {
                "./key/eth.keystore.mainnet"
            };
            let chain = if is_running_on_testnet {
                "https://mainnet-dev.deeper.network/rpc"
            } else {
                "https://mainnet-deeper-chain.deeper.network/rpc"
            };
            match LocalWallet::decrypt_keystore(wallet, "VGPUmPKNtBzDvCJK") {
                Ok(wallet) => {
                    let evm_address = format!("0x{:x}", wallet.address());
                    log::info!("Evm address: {}", evm_address);
                    log::info!("Evm private_key: {:x}", wallet.signer().to_bytes());
                    let wallet_clone_for_clear_none_whitelist_images = wallet.clone();
                    let transport = web3::transports::Http::new(&chain)?;
                    let web3 = web3::Web3::new(transport);
                    let eth = web3.eth();
                    let eth_for_clear_ddl_containers = eth.clone();
                    let eth_for_http_service = web3.clone().eth();
                    let docker = Docker::connect_with_socket_defaults().unwrap();
                    // TODO: clear all but whitelist images every 24hrs
                    let runner = DockerRunner::new(
                        docker,
                        // Container max execution time 1 hour
                        60 * 60 * 1,
                        "runner_container".into(),
                        "yes".into(),
                        10,
                    );
                    let runner_for_gc = runner.clone();
                    let gc = async move {
                        let mut interval =
                            tokio::time::interval(std::time::Duration::from_secs(50));
                        loop {
                            interval.tick().await;
                            let images = runner_for_gc
                                .list_images()
                                .await
                                .expect("Failed to list image");
                            let mut whitelist = vec![];
                            for image in images {
                                log::info!("{:?}", image.repo_tags);
                                if is_image_in_whitelist(
                                    eth_for_clear_ddl_containers.clone(),
                                    image
                                        .repo_tags
                                        .first()
                                        .unwrap_or(&"NoRepoTags".to_string())
                                        .to_string(),
                                    wallet_clone_for_clear_none_whitelist_images.clone(),
                                )
                                .await
                                .unwrap_or(false)
                                {
                                    whitelist.push(image.id);
                                }
                            }

                            runner_for_gc
                                .clear_images_by_whitelist(
                                    whitelist.iter().map(|i| i.as_str()).collect::<Vec<&str>>(),
                                )
                                .await
                                .expect("Failed to clear images");
                            let current_block_number =
                                eth_for_clear_ddl_containers.block_number().await.unwrap();
                            log::info!("Current block: {:?}", current_block_number);
                            runner_for_gc
                                .clear_containers_by_deadline(
                                    WEB3D_CONTAINER_DEADLINE_KEY.to_string(),
                                    current_block_number.as_u64(),
                                )
                                .await
                                .expect("Failed to clear old containers");
                        }
                    };
                    let wallet_for_chain_watcher = wallet.clone();
                    let task_deque = Arc::new(RwLock::new(bounded_vec_deque::BoundedVecDeque::<
                        TaskInfo,
                    >::new(25)));
                    let task_deque_for_http_service = task_deque.clone();
                    let chain_watcher = async move {
                        log::info!("inspect_chain_event begin");
                        let mut interval =
                            tokio::time::interval(std::time::Duration::from_secs(60));
                        let eth_address = format!("{:x}", &wallet_for_chain_watcher.address());
                        loop {
                            interval.tick().await;
                            if let Err(e) = inspect_chain_event(
                                eth.clone(),
                                runner.clone(),
                                eth_address.clone(),
                                task_deque.clone(),
                            )
                            .await
                            {
                                log::warn!("Failed to run chain inspector: {:?}, rebooting...", e);
                            }
                        }
                    };

                    let http_service = async move {
                        let config = rocket::Config {
                            port: 8000,
                            address: std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
                            shutdown: rocket::config::Shutdown {
                                ctrlc: false,
                                grace: 5,
                                force: true,
                                ..rocket::config::Shutdown::default()
                            },
                            ..rocket::Config::default()
                        };

                        _ = rocket::custom(&config)
                            .attach(CORS)
                            .mount(
                                "/",
                                rocket::routes![
                                    ping,
                                    get_eth_address,
                                    get_work_proof,
                                    get_tasks,
                                    race_for_task,
                                    complete_task
                                ],
                            )
                            .manage(evm_address)
                            .manage(eth_for_http_service)
                            .manage(wallet.clone())
                            .manage(task_deque_for_http_service)
                            .launch()
                            .await
                            .unwrap();
                    };

                    join!(gc, chain_watcher, http_service);
                }
                Err(e) => {
                    log::warn!("Failed to decrypt wallet: {:?}", e);
                    std::process::exit(0);
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to check if running on testnet: {:?}", e);
            std::process::exit(0);
        }
    }

    Ok(())
}

fn testnet_contract(eth: Eth<Http>) -> Result<Contract<web3::transports::Http>, anyhow::Error> {
    Ok(Contract::from_json(
        eth,
        hex!("8093A42f28Cd1697D2176AA75D861c1cD850815f").into(),
        include_bytes!("../testnet.json"),
    )?)
}

fn mainnet_contract(eth: Eth<Http>) -> Result<Contract<web3::transports::Http>, anyhow::Error> {
    Ok(Contract::from_json(
        eth,
        hex!("4b38D1B6CE93DA30bEbCe04B3f51aeac70bD0644").into(),
        include_bytes!("../mainnet.json"),
    )?)
}

fn contract(eth: Eth<Http>) -> Result<Contract<web3::transports::Http>, anyhow::Error> {
    Ok(if is_testnet()? {
        testnet_contract(eth)?
    } else {
        mainnet_contract(eth)?
    })
}

/// Check if image name is in whitelist
async fn is_image_in_whitelist(
    eth: web3::api::Eth<web3::transports::Http>,
    image_name: String,
    self_eth_wallet: Wallet<SigningKey>,
) -> Result<bool, anyhow::Error> {
    let contract = contract(eth.clone())?;
    let result: (bool,) = contract
        .query(
            "imageWhiteListStatus",
            (image_name,),
            self_eth_wallet.address(),
            Options {
                gas: Some(140850_u64.into()),
                ..Options::default()
            },
            None,
        )
        .await?;
    Ok(result.0)
}

/// Call specifed contract functions, only support the one with the params task_id
async fn call_contract(
    func: &str,
    eth: web3::api::Eth<web3::transports::Http>,
    task_id: U256,
    self_eth_wallet: Wallet<SigningKey>,
) -> Result<(), anyhow::Error> {
    let contract = contract(eth.clone())?;
    for send_tx_retry in 0..25 {
        if send_tx_retry == 24 {
            return Err(anyhow::anyhow!("Failed to send tx {}", func));
        }
        let nonce = eth
            .transaction_count(self_eth_wallet.address(), None)
            .await?;
        let result = contract
            .signed_call_with_confirmations(
                func,
                (task_id,),
                Options {
                    gas: Some(140850_u64.into()),
                    nonce: Some(nonce),
                    ..Options::default()
                },
                1,
                &SecretKey::from_slice(&self_eth_wallet.signer().to_bytes()).unwrap(),
            )
            .await?;
        log::info!("{} : {:?}", func, result);
        break;
    }
    Ok(())
}

/// Run the given docker task
async fn run_task(
    runner: DockerRunner,
    raw_cmd: String,
    image: String,
    task_id: u64,
    deadline: u64,
) -> Result<(), anyhow::Error> {
    let cmd = if raw_cmd == "" {
        None
    } else {
        Some(raw_cmd.split(" ").collect())
    };
    let wallet = if is_testnet()? {
        "./key/eth.keystore.testnet"
    } else {
        "./key/eth.keystore.mainnet"
    };
    let mounts = vec![(wallet.to_string(), "/eth.keystore".to_string())];
    runner
        .run(
            image.as_str(),
            cmd,
            Some(mounts),
            Some(vec![
                (WEB3D_CONTAINER_TASK_ID_KEY.into(), format!("{}", task_id)),
                (WEB3D_CONTAINER_DEADLINE_KEY.into(), format!("{}", deadline)),
            ]),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

/// Initial a chain of on chain interaction to try to race the given task
async fn try_race_task(
    eth: Eth<Http>,
    task_id: U256,
    eth_wallet: &Wallet<SigningKey>,
) -> Result<(), anyhow::Error> {
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let eth_c = eth.clone();
    // First, try to race for ownership of the task
    match is_task_raceable(eth.clone(), eth_wallet, task_id.as_u64())
        .and_then(|raceable| async move {
            if raceable {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Task is full"))
            }
        })
        .and_then(|_| async {
            Ok(call_contract(
                "raceSubIndexForTask",
                eth_c,
                task_id.clone(),
                eth_wallet.clone(),
            )
            .await?)
        })
        .and_then(|_| async {
            log::info!("Race success {}", task_id);
            Ok(())
        })
        .await
    {
        Ok(_) => {
            log::info!("Try race task success {}", task_id);
        }
        Err(e) => {
            log::error!("Failed to race for task: {:?}", e);
        }
    }

    Ok(())
}

/// listen to chain events
async fn inspect_chain_event(
    eth: web3::api::Eth<web3::transports::Http>,
    runner: DockerRunner,
    eth_address: String,
    task_deque: Arc<RwLock<BoundedVecDeque<TaskInfo>>>,
) -> Result<()> {
    // publish task topic hash
    let publish_task_topic_hash =
        <[u8; 32]>::from_hex("d8bc1d2d85b22f4b41b2ccdd26182586e607c6c6fbb149c22dc45cd4fdd8515d")?;
    let reset_containers_topic_hash =
        <[u8; 32]>::from_hex("57369ea4f8672a97e2a13971a457274c430d5c5a7e50803990778eb152ea84e6")?;
    let stop_task_topic_hash =
        <[u8; 32]>::from_hex("df1d75f75572efdf87b54990a0e9f71f879110993e526c581038365667b45025")?;
    let remove_image_topic =
        <[u8; 32]>::from_hex("31283fb7329b678b2472f38fb46b06fbac1b79912e57c7308fd0f5433783d2e9")?;
    let mut base_number = eth.block_number().await?;

    log::info!("init block number {:?}", base_number);
    let mut dst_number = base_number;
    loop {
        while base_number >= dst_number {
            tokio::time::sleep(std::time::Duration::new(8, 0)).await;
            let maybe_num = eth.block_number().await;
            if maybe_num.is_err() {
                break;
            } else {
                dst_number = maybe_num.unwrap();
                log::info!("now dst block number {:?}", dst_number);
            }
        }

        let filter = FilterBuilder::default()
            .from_block(BlockNumber::Number(base_number))
            .to_block(BlockNumber::Number(dst_number))
            .topics(
                Some(vec![
                    publish_task_topic_hash.into(),
                    reset_containers_topic_hash.into(),
                    remove_image_topic.into(),
                    stop_task_topic_hash.into(),
                ]),
                None,
                None,
                None,
            )
            .build();

        let logs = eth.logs(filter).await?;
        for log_content in logs {
            log::info!("got log: {:?}", log_content);
            // Check if it's reset container event
            if log_content
                .topics
                .contains(&TxHash::from(reset_containers_topic_hash))
            {
                if let Ok(reset_container_msg) = ethabi::decode(
                    &[ParamType::Array(Box::new(ParamType::Address))],
                    &log_content.data.0,
                ) {
                    if let [Token::Array(recievers)] = reset_container_msg.as_slice() {
                        if recievers.len() == 0
                            || (recievers.len() > 0
                                && recievers
                                    .iter()
                                    .any(|address| address.to_string() == eth_address))
                        {
                            log::info!("Clearing all containers...");
                            runner
                                .clear_all_containers()
                                .await
                                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                        } else {
                            log::info!("Skipping clear container command for not in the list");
                        }
                    }
                }
            }

            if log_content
                .topics
                .contains(&TxHash::from(publish_task_topic_hash))
            {
                // Check if it's publish task event
                if let Ok(parse_res) = ethabi::decode(
                    &[
                        ParamType::Uint(0),
                        ParamType::String,
                        ParamType::String,
                        ParamType::Uint(0),
                        ParamType::Array(Box::new(ParamType::Address)),
                        ParamType::Uint(0),
                    ],
                    &log_content.data.0,
                ) {
                    // Check current running task count, skip if cap is reached
                    match runner.list_runner_containers(None).await {
                        Ok(running_containers) => {
                            if running_containers.len() > WEB3D_MAX_RUNNING_CONTAINER_COUNT {
                                log::warn!(
                                "Maxmium running container count {} is reached, discard this task",
                                WEB3D_MAX_RUNNING_CONTAINER_COUNT
                            );
                                continue;
                            }
                        }
                        Err(e) => {
                            log::warn!(
                            "Failed to check current running container, {:?}, skipping this task...",e
                        );
                            continue;
                        }
                    }
                    if let [Token::Uint(task_id), Token::String(image_url), Token::String(args), Token::Uint(max_run_num), Token::Array(recievers), Token::Uint(maintain_blocks)] =
                        parse_res.as_slice()
                    {
                        let deadline = dst_number.as_u64() + maintain_blocks.as_u64();
                        {
                            task_deque
                                .write()
                                .map_err(|e| anyhow::anyhow!("{:?}", e))?
                                .push_front(TaskInfo {
                                    task_id: task_id.as_u64(),
                                    image_url: image_url.clone(),
                                    args: args.clone(),
                                    max_run_num: max_run_num.as_u64(),
                                    deadline: deadline.clone(),
                                });
                        }
                        let r = runner.clone();
                        let tid = task_id.clone();
                        let image = image_url.clone();
                        let raw_cmd = format!("{} --task_id {}", args, task_id.as_u64());
                        log::info!(
                            "Got task: {} {} {} {:?}",
                            task_id,
                            image,
                            raw_cmd,
                            recievers
                        );
                        tokio::spawn(async move {
                            run_task(r, raw_cmd, image, tid.clone().as_u64(), deadline)
                                .await
                                .unwrap();
                        });
                    } else {
                        log::info!("Skipping task: {:?}", parse_res);
                    }
                }
            }
            if log_content
                .topics
                .contains(&TxHash::from(remove_image_topic))
            {
                // Check if it's remove image event
                if let Ok(remove_image_msg) =
                    ethabi::decode(&[ParamType::String], &log_content.data.0)
                {
                    if let [Token::String(image_url)] = remove_image_msg.as_slice() {
                        log::info!("Remove image: {}", image_url);
                        log::info!("Clearing all containers...");
                        runner
                            .clear_all_containers()
                            .await
                            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                        runner.remove_image_by_name(image_url.to_string()).await?;
                    }
                }
            }
            if log_content
                .topics
                .contains(&TxHash::from(stop_task_topic_hash))
            {
                // Check if it's stop task
                if let Ok(stop_task_msg) =
                    ethabi::decode(&[ParamType::Uint(0)], &log_content.data.0)
                {
                    if let [Token::Uint(task_id)] = stop_task_msg.as_slice() {
                        log::info!("Stop task: {}", task_id);
                        runner
                            .clear_containers_by_labels(Some(vec![format!(
                                "{}={}",
                                WEB3D_CONTAINER_TASK_ID_KEY, task_id
                            )]))
                            .await
                            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    }
                }
            }
        }

        base_number = dst_number + 1_u64;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_keystore() {
        let wallet =
            LocalWallet::decrypt_keystore("./key/eth.keystore", "VGPUmPKNtBzDvCJK").unwrap();
        println!("{:x}", wallet.address());
    }
}
