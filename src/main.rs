use campy::{
    crypto::{encrypt_file, decrypt_file, new_keypair},
    utils::{save_key_to_file}
};

use clap::{Parser, Subcommand};

/// CAMPY tools
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypts a file
    Encrypt {
        /// File to encrypt
        #[arg(value_name = "FILE")]
        file: String,
        /// File path for the hex-encoded public key
        #[arg(short, long, default_value = "public_key.hex")]
        public_key_path: String,
        /// File path for the hex-encoded public key
        #[arg(short, long, default_value = "file_data.enc")]
        output_path: String,
    },
    /// Decrypts a file
    Decrypt {
        /// File to decrypt
        #[arg(value_name = "FILE")]
        file: String,
        /// File path for the hex-encoded public key
        #[arg(short, long, default_value = "secret_key.hex")]
        secret_key_path: String,
        /// File path for the hex-encoded public key
        #[arg(short, long, default_value = "file_data.enc")]
        output_path: String,
    },
    /// Generates a keypair
    Keypair {
        /// Save the keys to files instead of displaying them
        #[arg(long)]
        save: bool,
        /// File path for the hex-encoded secret|private key
        #[arg(short, long, default_value = "secret_key.hex")]
        secret_key_path: String,
        /// File path for the hex-encoded public key
        #[arg(short, long, default_value = "public_key.hex")]
        public_key_path: String,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { file, public_key_path, output_path } => {
            // Encrypt file with public key
            match encrypt_file(&file, &public_key_path, &output_path) {
                Ok(()) => println!("Encrypted file: {:?}", output_path),
                Err(e) => println!("Error encrypting file: {}", e),
            }
        },
        Commands::Decrypt { file, secret_key_path, output_path } => {
            // Decrypt file with secret key
            match decrypt_file(&file, &secret_key_path, &output_path) {
                Ok(()) => println!("Decrypted file: {:?}", output_path),
                Err(e) => println!("Error decrypting file: {}", e),
            }
        },
        Commands::Keypair  { save, secret_key_path, public_key_path } =>  {
            
            // Select the ECIES KeyPair to files or display them, add save option
            let (priv_key, pub_key) = new_keypair();
            let public_key_bytes = pub_key.serialize();
            let private_key_bytes = priv_key.serialize();

            println!("ECIES Generated Key Pair:");
            if save {
                // Save keys to files
                // Convert to hex and save
                save_key_to_file(&hex::encode(public_key_bytes), &public_key_path)?;
                save_key_to_file(&hex::encode(private_key_bytes), &secret_key_path)?;
                println!("Keys saved to {} and {}", secret_key_path, public_key_path);

            } else {
                // Display keys
                println!("Private Key: {:?}", hex::encode(private_key_bytes));
                println!("Public Key: {:?}", hex::encode(public_key_bytes));
            }
        },
    }

    Ok(())
}
