mod data_structures;
mod asp_message;

use std::io::{Error, ErrorKind};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{SigningKey};
use rsa::signature::{Keypair, RandomizedSigner, Verifier};
use rsa::sha2::{Sha256};
use std::net::{UdpSocket, SocketAddr, IpAddr};
use crate::asp_message::ASPMessage;

const PORTNUM: u16 = 56185;

#[derive(Debug)]
pub struct ASP {
    socket: UdpSocket,
    signing_key: SigningKey<Sha256>,
    pretty_name: String,
}

impl ASP {
    pub fn init(&mut self, private_key: RsaPrivateKey, address: IpAddr, name: String) -> Result<(), Error> {
        self.socket = UdpSocket::bind(SocketAddr::new(address, PORTNUM))?;
        self.socket.set_broadcast(true)?;
        self.signing_key = SigningKey::<Sha256>::new(private_key);
        // Make sure name is only alphanumeric
        self.pretty_name = name.chars().filter(|c| c.is_alphanumeric()).collect();
        Ok(())
    }
    pub fn broadcast(&self, msg: ASPMessage) -> Result<(), Error> {
        todo!()
    }
    pub fn try_receive(&self) -> Result<ASPMessage, Error> {
        todo!()
    }
}

fn data_err(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use rsa::pkcs1v15::Signature;
    use crate::data_structures::{AlarmDetail, AlarmType};
    use super::*;

    #[test]
    fn check_convert_and_back() {
        let mut rng = rand::thread_rng();
    
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = signing_key.verifying_key();
        // Generate payload
        let orig: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Silent),
            alarm_type: AlarmType::Intruder,
            signature: None,
            raw: None
        };
        // Sign
        let sig: Signature;
        match orig.sign(signing_key) {
            Ok(e) => sig = e,
            Err(e) => panic!("Sign Error: {}",e)
        }
        
    
        // Verify
        let raw: [u8; 41] = orig.try_into().unwrap();
        verifying_key.verify(raw.as_slice(), &sig).expect("Verification failed!");
}
}
