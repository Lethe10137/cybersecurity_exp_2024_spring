use std::vec;

use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, WriteBuffer};

use crypto::blowfish::Blowfish;
use rand::Rng;
use ring::{digest, pkcs8};

use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor, SymmetricCipherError};

use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
// use ring::digest;

pub fn aes_encrypt(key: &[u8], content: &Vec<u8>) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut output: Vec<u8> = vec![];
    output.resize(16, 0);
    let mut rng = rand::thread_rng();
    rng.fill(output.as_mut_slice());

    assert_eq!(key.len(), 32);

    let mut encryptor = cbc_encryptor(
        KeySize::KeySize256,
        key,
        &output.as_slice(),
        blockmodes::PkcsPadding,
    );

    let mut read_buffer = RefReadBuffer::new(content.as_slice());
    let cipher_len = (content.len() / 16 + 1) * 16;

    output.resize(cipher_len + 16, 0);
    let mut write_buffer = RefWriteBuffer::new(&mut output.as_mut_slice()[16..]);

    encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

    Ok(output)
}

pub fn aes_decrypt(key: &[u8], cipher_text: &Vec<u8>) -> Result<Vec<u8>, SymmetricCipherError> {
    assert_eq!(key.len(), 32);
    let mut read_buffer = RefReadBuffer::new(&cipher_text.as_slice()[16..]);
    let mut plaintext_u8 = vec![];
    plaintext_u8.resize(cipher_text.len(), 1);
    let mut write_buffer = RefWriteBuffer::new(&mut plaintext_u8);

    let mut decryptor = cbc_decryptor(
        KeySize::KeySize256,
        key,
        &cipher_text.as_slice()[0..16],
        blockmodes::PkcsPadding,
    );

    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;

    let remain = write_buffer.remaining();
    plaintext_u8.resize(plaintext_u8.len() - remain, 0);
    Ok(plaintext_u8)
}

pub fn blowfish_encrypt(key: &[u8], content: &[u8]) -> Vec<u8> {
    let blowfish: Blowfish = Blowfish::new(key);
    let padding = 8 - content.len() % 8;
    let mut result = vec![];

    let mut cipher: [u8; 8] = [0; 8];
    let mut padding: [u8; 8] = [padding as u8; 8];

    for chunk in content.chunks(8) {
        if chunk.len() == 8 {
            blowfish.encrypt_block(&chunk, &mut cipher);
            result.extend(cipher);
        } else {
            padding
                .iter_mut()
                .zip(chunk.iter())
                .for_each(|(t, s)| *t = *s);
        }
    }
    blowfish.encrypt_block(&padding, &mut cipher);
    result.extend(cipher);
    result
}

pub fn blowfish_decrypt(key: &[u8], cipher: &Vec<u8>) -> Vec<u8> {
    assert!(cipher.len() % 8 == 0);
    let mut result = vec![];
    let blowfish: Blowfish = Blowfish::new(key);
    let mut output: [u8; 8] = [0; 8];
    for chunk in cipher.chunks(8) {
        blowfish.decrypt_block(chunk, &mut output);
        result.extend(output);
    }
    if let Some(len) = result.pop() {
        for _ in 1..len {
            result.pop();
        }
    }

    result
}

pub fn rsa_public_key_export(kpub: &RsaPublicKey) -> Vec<u8> {
    kpub.to_pkcs1_der().unwrap().as_ref().to_vec()
}

pub fn rsa_public_key_import(bytes: &[u8]) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    Ok(RsaPublicKey::from_pkcs1_der(bytes)?)
}

pub fn rsa_private_key_generate() -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, 2048).unwrap()
}

pub fn hash_key(key_phrase: &str) -> Vec<u8> {
    let digest_data = digest::digest(&digest::SHA256, key_phrase.as_bytes());
    digest_data.as_ref().to_vec()
}
