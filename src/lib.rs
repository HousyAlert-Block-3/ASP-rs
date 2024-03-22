use std::io;
use std::io::{Error, Read};
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
        todo!()
    }
    pub fn try_receive(&self) -> Result<ASPMessage, io::Error> {
        todo!()
    }
}

pub struct ASPMessage {
    activator_name: String,
    alarm_details: Vec<AlarmDetail>,
    alarm_type: AlarmType,
    signature: Signature,
    raw: [u8; 37],
}
impl TryFrom<&[u8]> for ASPMessage {
    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let message_vec = value.to_vec();
        if message_vec.len() != 164 {
            return Err(data_err("Incorrect message length"));
        }
        let namevec: Vec<u8> = message_vec[0..32].to_vec();
        let alarm_code = message_vec[32];
        let timebytes: [u8; 4] = message_vec[33 .. 38].try_into()
            .map_err(|_err|data_err("Invalid Timestamp"))?;

        Ok(ASPMessage {
            activator_name: String::from_utf8(namevec)
                .map_err(|_err|Error::new(io::ErrorKind::InvalidData,"Bad name data"))?,
            alarm_code: ,
            signature: Signature::try_from(sigarray)?
        })
    }
    type Error = Error;
}

impl ASPMessage{
    fn verify_sig(&self, pubkey: VerifyingKey<Sha256>) -> Result<(), io::Error> {
        pubkey.verify(&self.raw, &self.signature)
            .map_err(|err|data_err(format!("Signature Invalid! {}", err.to_string()).as_str()))?;
        Ok(())
    }
}

fn data_err(msg: &str) -> io::Error {
    Error::new(io::ErrorKind::InvalidData, msg)
}

enum AlarmDetail {
    Silent,
    Browser,
    Lockdown,
    Evacuate,
}

enum AlarmType {
    Intruder,
    Fire
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
