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
    use std::time;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use crate::data_structures::{AlarmDetail, AlarmType};
    use super::*;

    fn test_generate_rand_key() -> SigningKey<Sha256> {
        let mut rng = rand::thread_rng();
        // generate random signing key
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        SigningKey::<Sha256>::new(private_key)
    }

    #[test]
    fn sign_and_verify() {
        let signing_key = test_generate_rand_key();
        let verifying_key = signing_key.verifying_key();
        // Generate payload
        let mut orig: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Silent),
            alarm_type: AlarmType::Intruder,
            signature: None,
            raw: None
        };
        // Sign
        orig.sign(&signing_key).unwrap();

        // Verify
        orig.verify_sig(&verifying_key).unwrap();
    }

    #[test]
    fn data_encode_decode() {
        let signing_key = test_generate_rand_key();
        let verifying_key = signing_key.verifying_key();
        let mut orig: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Silent, AlarmDetail::Browser),
            alarm_type: AlarmType::Intruder,
            signature: None,
            raw: None
        };
        orig.sign(&signing_key).unwrap();
        let raw: Vec<u8> = orig.clone().try_into().unwrap();
        let new: ASPMessage = ASPMessage::try_from(raw.as_slice()).expect("Conversion from raw failed!");
        assert_eq!(&orig.activator_name, &new.activator_name);
        assert_eq!(&orig.alarm_type, &new.alarm_type);
        assert_eq!(&orig.alarm_details.len(), &new.alarm_details.len());
        for i in  0 .. orig.alarm_details.len()  {
            assert_eq!(orig.alarm_details[i], new.alarm_details[i]);
        }
    }
    #[test]
    fn reject_invalid_timestamp() {
        let signing_key = test_generate_rand_key();
        let verifying_key = signing_key.verifying_key();
        let mut mesg: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Silent, AlarmDetail::Evacuate),
            alarm_type: AlarmType::Intruder,
            signature: None,
            raw: None
        };
        mesg.encode_body().unwrap();
        let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
        mesg.override_timestamp(now.as_secs() - 240).unwrap();
        mesg.sign(&signing_key).unwrap();
        let raw: Vec<u8> = mesg.clone().try_into().unwrap();
        match ASPMessage::try_from(raw.as_slice()) {
            Ok(_) => panic!("Accepted out of date timestamp!"),
            Err(_) => return
        }
    }

    #[test]
    fn reject_tampered_signature() {
        let signing_key = test_generate_rand_key();
        let verifying_key = signing_key.verifying_key();
        let mut mesg: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Evacuate),
            alarm_type: AlarmType::Intruder,
            signature: None,
            raw: None
        };
        mesg.sign(&signing_key).unwrap();
        // tamper with timestamp *after* signing
        mesg.override_timestamp(946702800).unwrap();
        // attempt to verify
        match mesg.verify_sig(&verifying_key){
            Ok(_) => panic!("accepted signature of tampered payload"),
            Err(_) => return
        }
    }

}
