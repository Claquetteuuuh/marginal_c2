use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

extern crate hex;
extern crate rand;
extern crate rsa;

pub fn test() {
    let bits = 2048;

    let priv_key = generate_private_key(bits);

    let data = b"hello world";

    let enc_data = encrypt(&priv_key, data);
    assert_ne!(&data[..], &enc_data[..]);

    let dec_data = decrypt(&priv_key, enc_data);
    assert_eq!(&data[..], &dec_data[..]);
}

pub fn generate_private_key(bits: usize) -> RsaPrivateKey {
    let mut rng = rand::thread_rng(); // rand@0.8
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    return priv_key;
}

pub fn encrypt(priv_key: &RsaPrivateKey, data: &[u8; 11]) -> Vec<u8> {
    let mut rng = rand::thread_rng(); // rand@0.8
    let pub_key = RsaPublicKey::from(priv_key);

    let enc_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])
        .expect("failed to encrypt");

    return enc_data;
}

pub fn decrypt(priv_key: &RsaPrivateKey, enc_data: Vec<u8>) -> Vec<u8> {
    let dec_data = priv_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .expect("failed to decrypt");

    return dec_data;
}
