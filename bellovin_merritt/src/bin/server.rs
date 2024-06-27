use bellovin_merritt::protocol::*;
use bellovin_merritt::utils::*;

use rand::Rng;

use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;

use tokio::net::TcpListener;

use std::str::FromStr;
use std::vec;

use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref PASSWORD: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("ming", "hello_world_2024");
        m.insert("lethe", "123459_2nd");
        m.insert("archi", "128n_23h8");
        m
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    println!("Server running on 127.0.0.1:8080");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let client_address = format!("{:?}", socket.peer_addr()?);

        println!("Client connected: {}", client_address);

        tokio::spawn(async move {
            let pubkey: RsaPublicKey;
            let pw;
            match read_message(Box::new(&mut socket)).await {
                Ok((1, content)) => {
                    if content.len() == 2 {
                        let username = std::str::from_utf8(&content[0]);
                        if username.is_err(){
                            println!("illegal username!");
                            return;
                        }
                        let username = username.unwrap();
                        if let Some(password) = PASSWORD.get(&username){
                            pw = hash_key(&password);
                            println!("{:?}", pw);
                            if let Ok(pubkey_bytes) = aes_decrypt(pw.as_slice(), &content[1]) {
                                if let Ok(p) = rsa_public_key_import(&pubkey_bytes[..]) {
                                    pubkey = p;
                                } else {
                                    println!("wrong password!");
                                    return;
                                }
                            } else {
                                println!("wrong password!");
                                return;
                            }
                        }else{
                            println!("wrong password");
                            return;
                        }
                    } else {
                        println!("unexpected fields");
                        return;
                    }
                }
                Ok((_, _)) => {
                    println!("unexpected id");
                    return;
                }
                Err(e) => {
                    dbg!(e);
                    return;
                }
            }

            let mut session_key: Vec<u8> = vec![0; 32];

            let mut rng = rand::rngs::OsRng;
            rng.fill(session_key.as_mut_slice());
            println!("session key:\n{:?}", session_key);

            let en_sk = pubkey
                .encrypt(&mut rng, Pkcs1v15Encrypt, &session_key[..])
                .expect("failed to encrypt");

            if let Ok(en_en_sk) = aes_encrypt(&pw, &en_sk) {
                write_message(2, &vec![&en_en_sk[..]], Box::new(&mut socket))
                    .await
                    .unwrap();
            } else {
                println!("failed to encrypt");
                unreachable!();
            }

            let mut na_nb: Vec<u8>;
            match read_message(Box::new(&mut socket)).await {
                Ok((3, content)) => {
                    if content.len() == 1 {
                        na_nb = blowfish_decrypt(&session_key, &content[0]);
                    } else {
                        println!("unexpected fields");
                        return;
                    }
                }
                Ok((_, _)) => {
                    println!("unexpected id");
                    return;
                }
                Err(e) => {
                    dbg!(e);
                    return;
                }
            }

            let len_na = na_nb.len();
            println!("NA:\n{:?}", &na_nb[..]);

            for _ in 0..32 {
                na_nb.push(rng.gen());
            }

            println!("NB:\n{:?}", &na_nb[len_na..]);

            let en_na_nb = blowfish_encrypt(&session_key, &na_nb.as_slice());
            write_message(4, &vec![&en_na_nb[..]], Box::new(&mut socket))
                .await
                .unwrap();

            let nb: Vec<u8>;

            match read_message(Box::new(&mut socket)).await {
                Ok((5, content)) => {
                    if content.len() == 1 {
                        nb = blowfish_decrypt(&session_key, &content[0]);
                    } else {
                        println!("unexpected fields");
                        return;
                    }
                }
                Ok((_, _)) => {
                    println!("unexpected id");
                    return;
                }
                Err(e) => {
                    dbg!(e);
                    return;
                }
            }

            for i in 0..32 {
                if nb[i] != na_nb[len_na + i] {
                    println!("nb 校验失败");
                }
            }
            println!("NB back:\n{:?}", &nb[..]);

            let data = blowfish_encrypt(&session_key, "secret infomation here!".as_bytes());
            write_message(0, &vec![&data[..]], Box::new(&mut socket))
                .await
                .unwrap();
        });
    }
}
