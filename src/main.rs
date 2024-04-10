use std::collections::HashMap;
use std::io::{BufReader,Read,Write};
use clap::{Parser, Subcommand};
use rand::rngs::ThreadRng;
use rsa::{pkcs1::EncodeRsaPrivateKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,pkcs1::EncodeRsaPublicKey,pkcs1::DecodeRsaPublicKey,pkcs1::DecodeRsaPrivateKey};
use rsa::pkcs1::LineEnding;
use std::path::Path;
use std::fs::File;
use rand::RngCore;
use rand::Rng;
use serde::{Serialize, Deserialize};
use rpassword::read_password;

#[derive(Parser)]
#[command(name = "Password Manager")]
#[command(version = "1.0")]
#[command(about = "Encrypts and Saves your Passwords",long_about = None)]
struct Cli{
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Add {
        acc_name: Option<String>,
    },
    Get {
        acc_name: Option<String>
    },
    Remove {
        acc_name: Option<String>
    },
    All {

    },
}

#[derive(Serialize, Deserialize)]
struct ThreadRngState {
    state: [u8; 32]
}



#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct Password_Manager {
    PasswordManager: std::collections::HashMap<String,Vec<u8>>,
    PrivateKey: RsaPrivateKey,
    PublicKey: RsaPublicKey,
    Rng: ThreadRng,
}

impl Password_Manager {
    fn new() -> Self {
        let (private_key,public_key,rng) = get_or_load_keys();
        Self {
            PasswordManager: HashMap::new(),
            PrivateKey: private_key,
            PublicKey: public_key,
            Rng: rng,
        }

    }

    fn add_(&mut self,acc_name: Option<String>){
        let acc_name_str: String = match acc_name {
            Some(s) => s,
            None => String::new(), 
        };

        std::io::stdout().flush().unwrap();
        println!("Enter Password :");
        let password_str = read_password().unwrap();
        let password_ = password_str.as_bytes();
        let enc_data = self.PublicKey.encrypt(&mut self.Rng,Pkcs1v15Encrypt,&password_[..]).expect("Failed to Encrypt Password");
        self.PasswordManager.insert(acc_name_str, enc_data);

        let hash_path = "C:\\Passwords\\hash.json";
        save_hashmap_to_file(&self.PasswordManager, hash_path).expect("Failed to save Password");

        println!("Password Saved Successfully!");
    }
    
    fn get_(&mut self,acc_name: Option<String>){
        let acc_name_str: String = match acc_name {
            Some(s) => s,
            None => String::new(), // or any default value you want
        };

        let hash_path = "C:\\Passwords\\hash.json";

        self.PasswordManager = get_hashmap_from_file(hash_path);
        let enc_pass = self.PasswordManager.get(&acc_name_str);
        let dec_pass = self.PrivateKey.decrypt(Pkcs1v15Encrypt, enc_pass.unwrap()).expect("Failed to Decrypt Password");
        let dec_pass_str = String::from_utf8_lossy(&dec_pass);
        println!("Password : {}",dec_pass_str);
    }
    
    fn remove_(&mut self,acc_name: Option<String>){
        let acc_name_str: String = match acc_name {
            Some(s) => s,
            None => String::new(), // or any default value you want
        };
        let hash_path = "C:\\Passwords\\hash.json";

        remove_and_save( hash_path,&acc_name_str);

        println!("Password Successfully Removed!!");
    }
    
    fn all_(&mut self){
        let hash_path = "C:\\Passwords\\hash.json";

        self.PasswordManager = get_hashmap_from_file(hash_path);

        println!("Saved Passwords for ->");
        for key in self.PasswordManager.keys() {
            println!("{}",key);
        }

    }
}


#[allow(non_snake_case)]
fn main(){
    let cli: Cli = Cli::parse();
    folder();
    let mut PasswordManager = Password_Manager::new();


    match cli.command {
        Some(Commands::Add {acc_name}) =>{
            PasswordManager.add_(acc_name);
        }
        Some(Commands::Get {acc_name}) => {
            PasswordManager.get_(acc_name);
        },
        Some(Commands::Remove {acc_name}) => {
            PasswordManager.remove_(acc_name);
        },
        Some(Commands::All {}) => {
            PasswordManager.all_();
        },
       _ => println!("Invalid Command"),
    }

}

fn get_or_load_keys() -> (RsaPrivateKey,RsaPublicKey,ThreadRng) {
    
    let private_key_file_path = "C:\\Passwords\\private_key.pem";
    let public_key_file_path = "C:\\Passwords\\public_key.pem";
    let rng_file_path = "C:\\Passwords\\rng.json";
    if file_exists(private_key_file_path) && file_exists(public_key_file_path) && file_exists(rng_file_path){
        let priv_k = read_pem(private_key_file_path).unwrap();
        let pub_k = read_pem(public_key_file_path).unwrap();
        let priv_key = RsaPrivateKey::from_pkcs1_pem(&priv_k).expect("Failed To read Pem File");
        let pub_key = RsaPublicKey::from_pkcs1_pem(&pub_k).expect("Failed to read Pem File");
        let rng = load_threadrng_state(rng_file_path).unwrap();
        return (priv_key,pub_key,rng);
    }
    

    // Generating the key
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    
    priv_key.write_pkcs1_pem_file(private_key_file_path, LineEnding::LF).expect("Failed to Store Private Key");
    pub_key.write_pkcs1_pem_file(public_key_file_path,LineEnding::LF).expect("Failed to Store Public key");
    save_rng(rng_file_path,&rng);
    (priv_key,pub_key,rng)
}


fn file_exists(file_path: &str) -> bool {
    let path = Path::new(file_path);
    path.exists()
}

fn read_pem(file_path: &str) -> Option<String> {
    let file = File::open(file_path).expect("Failed to open File");
    let mut reader = BufReader::new(file);

    let mut contents = String::new();
    reader.read_to_string(&mut contents).expect("Failed to read File");

    Some(contents)
}

fn save_rng(file_path: &str,rng: &ThreadRng){
    let state = ThreadRngState {
        state : rng.clone().gen()
    };
    let serialized_state = serde_json::to_string(&state).expect("Failed to Save Rng");
    std::fs::write(file_path, serialized_state).expect("Failed to write ThreadRng state to file.");
}

fn load_threadrng_state(file_path: &str) -> Option<ThreadRng> {
    let file_contents = std::fs::read_to_string(file_path).ok()?;
    
    let mut state: ThreadRngState = serde_json::from_str(&file_contents).ok()?;
    
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut state.state);
    
    Some(rng)
}

fn save_hashmap_to_file(map: &HashMap<String,Vec<u8>>, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {

    if file_exists(file_path) {
        let mut hash = get_hashmap_from_file(file_path);
        hash.extend(map.clone());
        let file = File::create(file_path)?;
        serde_json::to_writer(file, &hash)?;
    }
    else{
        let file = File::create(file_path)?;
        serde_json::to_writer(file, &map)?;
    }
    Ok(())
}

fn get_hashmap_from_file(file_path: &str) -> HashMap<String, Vec<u8>> {
    let content = std::fs::read_to_string(file_path).ok().expect("Failed to read Json File");

    let hash: HashMap<String,Vec<u8>> = serde_json::from_str(&content).ok().expect("Failed to convert json to HashMap");

    hash
}

fn remove_and_save(file_path: &str,key: &str) {
    let mut hash = get_hashmap_from_file(file_path);
    if hash.contains_key(key) {
        hash.remove(key);
        let file = File::create(file_path).expect("Failed to open File");
        serde_json::to_writer(file, &hash).expect("Failed to write");
    }
    else{
        println!("No such key");
    }
}

fn folder() {
    let folder_path = "C:\\Passwords";
    if let Err(e) = std::fs::metadata(&folder_path) {
        match e.kind() {
            std::io::ErrorKind::NotFound => {
                // Folder does not exist, so create it
                if let Err(err) = std::fs::create_dir_all(&folder_path) {
                    eprintln!("Error creating folder: {}", err);
                } else {
                    // println!("Folder created successfully!");
                }
            }
            _ => {
                eprintln!("Error accessing folder: {}", e);
            }
        }
    } else {
        // println!("Folder already exists!");
    }
}