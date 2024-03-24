use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use rsa::pkcs1v15::SigningKey;
use rsa::RsaPrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, Verifier};
use crate::asp_message::{ASPMessage, MESG_LEN};
use crate::data_structures::{AlarmDetail, AlarmType};
use log::{info, warn, debug, error};

mod data_structures;
mod asp_message;

const PORTNUM: u16 = 56185;

#[derive(Debug)]
pub struct ASP {
    socket: UdpSocket,
    signing_key: SigningKey<Sha256>,
    pretty_name: String,
}

impl ASP {
    pub fn new(signing_key: &SigningKey<Sha256>, name: &str) -> Result<ASP, Error> {
        let any_iface = IpAddr::from([0,0,0,0]);
        let mut instance: ASP = ASP {
            socket: UdpSocket::bind(SocketAddr::new(any_iface, PORTNUM))?,
            signing_key: signing_key.clone(),
            pretty_name: name.chars().filter(|c| c.is_alphanumeric()).collect(),
        };
        instance.socket.set_broadcast(true)?;
        instance.socket.set_nonblocking(true)?;
        Ok(instance)
    }
    pub fn broadcast(&self, alm_type: AlarmType, details: Vec<AlarmDetail>) -> Result<(), Error> {
        let mut mesg: ASPMessage = ASPMessage {
            activator_name: self.pretty_name.clone(),
            alarm_details: details,
            alarm_type: alm_type,
            id: rand::random(),
            signature: None,
            raw: None
        };
        self.broadcast_message(mesg)
    }
    
    pub fn broadcast_message(&self, mut message: ASPMessage) -> Result<(), Error> {
        message.sign(&self.signing_key)?;
        let raw: Vec<u8> = message.try_into().unwrap();
        let dest = SocketAddrV4::new(Ipv4Addr::new(255,255,255,255), PORTNUM);
        self.socket.send_to(raw.as_slice(), dest)?;
        Ok(())
    }
    pub fn try_receive(&self) -> Result<Option<ASPMessage>, Error> {
        let mut mesgbuff: [u8; MESG_LEN] = [0; MESG_LEN];
        match self.socket.recv_from(&mut mesgbuff){
            Ok(recdat) => {
                info!("Got message from {}", recdat.1);
                if recdat.0 != MESG_LEN {
                    warn!("Received payload length wrong! Expected {}, got {}.",MESG_LEN, recdat.0);
                    return Err(data_err("Received data of incorrect length"));
                }
                Ok(Some(ASPMessage::try_from(mesgbuff.as_slice())?))
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Ok(None),
                _ => Err(e)
            }
        }
    }
}

fn data_err(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
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
            id: rand::random(),
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
        let mut orig: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Silent, AlarmDetail::Browser),
            alarm_type: AlarmType::Intruder,
            id: rand::random(),
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
    fn reject_tampered_payload() {
        let signing_key = test_generate_rand_key();
        let verifying_key = signing_key.verifying_key();
        let mut mesg: ASPMessage = ASPMessage {
            activator_name: "test".to_string(),
            alarm_details: vec!(AlarmDetail::Evacuate),
            alarm_type: AlarmType::Intruder,
            id: rand::random(),
            signature: None,
            raw: None
        };
        mesg.sign(&signing_key).unwrap();
        // tamper with payload after signing
        let mut tampered: Vec<u8> = mesg.raw.unwrap();
        tampered[4] = tampered[4] ^ 0xFF;
        mesg.raw = Some(tampered);
        // attempt to verify
        match mesg.verify_sig(&verifying_key){
            Ok(_) => panic!("accepted signature of tampered payload"),
            Err(_) => return
        }
    }
    #[test]
    fn send_activation_command() {
        let signing_key = test_generate_rand_key();
        let verifying_key = signing_key.verifying_key();
        let asp_inst = ASP::new(&signing_key, "Unit Tests").unwrap();
        asp_inst.broadcast(AlarmType::Intruder, vec!(AlarmDetail::Lockdown)).unwrap()
    }

}
