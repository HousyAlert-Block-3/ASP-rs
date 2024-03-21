use std::io;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Digest, Sha256};
use std::net::{UdpSocket, SocketAddr, IpAddr};

const PORTNUM: u16 = 56185;
pub struct ASP {
    socket: UdpSocket,
    signing_key: SigningKey<Sha256>,
    pretty_name: String,
}

impl ASP {
    pub fn init(&mut self, private_key: RsaPrivateKey, address: IpAddr, name: String) -> Result<(), io::Error> {
        self.socket = UdpSocket::bind(SocketAddr::new(address, PORTNUM))?;
        self.socket.set_broadcast(true)?;
        self.signing_key = SigningKey::<Sha256>::new(private_key);
        // Make sure name is only alphanumeric
        self.pretty_name = name.chars().filter(|c| c.is_alphanumeric()).collect();
        Ok(())
    }
    pub fn broadcast(&self, msg: ASPMessage) -> Result<(), io::Error> {
        
        Ok(())
    }
    pub fn try_receive(&self) -> Result<ASPMessage, io::Error> {
        
    }
}

pub struct ASPMessage {
    activator_name: String,
    alarm_code: u8, //Raw byte of data
    signature: Signature
}

pub fn example1() -> rsa::signature::Result<()> {

    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();

// Sign
    let data = b"hello world";
    let signature = signing_key.sign_with_rng(&mut rng, data);

// Verify
    verifying_key.verify(data, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = example1();
        result.expect("fail!")
    }
}
