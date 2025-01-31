use std::env;
use clap::{Parser, Subcommand};

pub mod authentication {
    tonic::include_proto!("authentication");
}

use authentication::authentication_client::AuthenticationClient;


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>
}

#[derive(Subcommand)]
enum Commands {
    SignIn {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String
    },
    SignUp {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String
    },
    SignOut {
        #[arg(short, long)]
        session_token: String
    },
}

const AUTH_SERVICE_IP: &str = "AUTH_SERVICE_IP";
const DEFAULT_AUTH_SERVICE_IP: &str = "[::0]"; 

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_ip = env::var(AUTH_SERVICE_IP).unwrap_or(DEFAULT_AUTH_SERVICE_IP.to_owned());
    let mut client = AuthenticationClient::connect(format!("http://{}:50051", auth_ip)).await?;

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::SignIn { username, password }) => {
            let request = tonic::Request::new(authentication::SignInRequest {
                username: username.to_owned(),
                password: password.to_owned(),
            });
            let response = client.sign_in(request).await?;
            println!("{:#?}", response);
        },
        Some(Commands::SignUp { username, password }) => {
            let request = tonic::Request::new(authentication::SignUpRequest {
                username: username.to_owned(),
                password: password.to_owned(),
            });
            let response = client.sign_up(request).await?;
            println!("{:#?}", response);
        },
        Some(Commands::SignOut { session_token }) => {
            let request = tonic::Request::new(authentication::SignOutRequest {
                session_token: session_token.to_owned(),
            });
            let response = client.sign_out(request).await?;
            println!("{:#?}", response);
        },
        None => println!("No command provided"),
    }

    Ok(())
}
