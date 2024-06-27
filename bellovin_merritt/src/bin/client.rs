use bellovin_merritt::protocol::*;
use bellovin_merritt::utils::*;
use rand::Rng;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::process::exit;
use std::{env, io};
use std::{net::SocketAddr, vec};
use tokio::net::TcpStream;

fn get_server_address() -> String {
    match env::var("SERVER") {
        Ok(val) => val,
        Err(_) => "127.0.0.1:8080".to_string(),
    }
}

#[tokio::main]
async fn main() {
    let mut username = String::new();
    let mut password = String::new();

    println!("Enter username");
    io::stdin().read_line(&mut username).unwrap();
    username.pop();
    println!("Enter password");
    io::stdin().read_line(&mut password).unwrap();
    password.pop();

    let pw = hash_key(&password);
    println!("{:?}", pw);

    let addr = get_server_address().parse::<SocketAddr>().unwrap();

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();

    let result = socket.connect(&SockAddr::from(addr));

    if let Err(err) = result {
        dbg!(err);
        exit(-1);
    };

    let mut stream = TcpStream::from_std(std::net::TcpStream::from(socket)).unwrap();

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let pub_key_bytes = rsa_public_key_export(&pub_key);
    let encrypted_pub_bytes = aes_encrypt(pw.as_slice(), &pub_key_bytes).expect("fail to encrypt");

    write_message(
        1,
        &vec![username.as_bytes(), encrypted_pub_bytes.as_slice()],
        Box::new(&mut stream),
    )
    .await
    .unwrap();

    let (id, content) = read_message(Box::new(&mut stream))
        .await
        .expect("connection closed");
    assert!(id == 2);
    assert!(content.len() == 1);
    let en_en_session_key = &content[0];
    let en_session_key = aes_decrypt(pw.as_slice(), en_en_session_key).expect("fail to decrypt");
    let session_key = priv_key
        .decrypt(Pkcs1v15Encrypt, &en_session_key)
        .expect("failed to decrypt");

    println!("session key:\n{:?}", session_key);

    let mut na: Vec<u8> = vec![0; 32];

    let mut rng = rand::rngs::OsRng;
    rng.fill(na.as_mut_slice());
    println!("NA:\n{:?}", na);

    let en_na = blowfish_encrypt(&session_key, &na);

    write_message(3, &vec![en_na.as_slice()], Box::new(&mut stream))
        .await
        .unwrap();

    let (id, content) = read_message(Box::new(&mut stream)).await.unwrap();
    assert!(id == 4);
    assert!(content.len() == 1);

    let na_nb = blowfish_decrypt(&session_key, &content[0]);

    let pass: bool = na.iter().zip(na_nb.iter()).all(|(x, y)| x == y) && na_nb.len() > na.len();

    if !pass {
        println!("nanb和na不一致");
        return;
    }
    println!("NB:\n{:?}", &na_nb[na.len()..]);

    let en_nb = blowfish_encrypt(&session_key, &na_nb[na.len()..]);

    write_message(5, &vec![en_nb.as_slice()], Box::new(&mut stream))
        .await
        .unwrap();

    let (id, content) = read_message(Box::new(&mut stream)).await.unwrap();

    let message = blowfish_decrypt(&session_key, &content[0]);

    println!("{:?}", std::str::from_utf8(&message[..]));
}
