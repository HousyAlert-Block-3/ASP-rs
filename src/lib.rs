use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use rsa::pkcs1v15::SigningKey;

use rsa::sha2::Sha256;

use crate::asp_message::{ASPMessage, MESG_LEN};
use crate::data_structures::{AlarmDetail, AlarmType};
use log::{info, warn};

pub mod data_structures;
pub mod asp_message;

const PORTNUM: u16 = 56185;

#[derive(Clone)]
#[derive(Debug)]
pub struct ASP {
    socket: Arc<UdpSocket>,
    signing_key: SigningKey<Sha256>,
    pretty_name: String,
}
/// Struct that stores the context for ASP handling, such as the name and socket.
impl ASP {
    pub async fn new(signing_key: &SigningKey<Sha256>, name: &str) -> Result<ASP, Error> {
        // Creates a new instance of ASP struct with the given signing key and name
        let sock = UdpSocket::bind(SocketAddr::new(IpAddr::from([0,0,0,0]), PORTNUM)).await?;
        let instance: ASP = ASP {
            socket: Arc::new(sock),
            signing_key: signing_key.clone(),
            pretty_name: name.chars().filter(|c| c.is_alphanumeric()).collect(),
        };
        instance.socket.set_broadcast(true)?;
        info!("Registered new socket for ASP");
        Ok(instance)
    }
    pub async fn broadcast(&self, alm_type: AlarmType, details: Vec<AlarmDetail>) -> Result<(), Error> {
        // Broadcasts the given alarm message
        let mesg: ASPMessage = ASPMessage {
            activator_name: self.pretty_name.clone(),
            alarm_details: details,
            alarm_type: alm_type,
            id: rand::random(),
            signature: None,
            raw: None
        };
        self.broadcast_message(mesg).await
    }

    pub async fn broadcast_message(&self, mut message: ASPMessage) -> Result<(), Error> {
        // Signs the given message and broadcasts it to all devices in the network
        message.sign(&self.signing_key)?;
        let raw: Vec<u8> = message.try_into().unwrap();
        let dest = SocketAddrV4::new(Ipv4Addr::new(255,255,255,255), PORTNUM);
        self.socket.send_to(raw.as_slice(), dest).await?;
        Ok(())
    }
    pub async fn try_receive(&self) -> Result<Option<ASPMessage>, Error> {
        // Attempts to receive a message from the network
        let mut mesgbuff: [u8; MESG_LEN] = [0; MESG_LEN];
        match self.socket.recv_from(&mut mesgbuff).await{
            Ok(recdat) => {
                info!("Got message from {}", recdat.1);
                if recdat.0 != MESG_LEN {
                    warn!("Received payload length wrong! Expected {}, got {}.",MESG_LEN, recdat.0);
                    return Err(data_err("Received data of incorrect length"));
                }
                Ok(Some(ASPMessage::try_from(mesgbuff.as_slice())?))
            }
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock => Ok(None),
                _ => Err(e)
            }
        }
    }
}

// impl Clone for ASP {
//     fn clone(&self) -> ASP {
//         todo!();
//     }
// }

fn data_err(msg: &str) -> Error {
    // Helper function to create an error with the given message
    Error::new(ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
    use rsa::signature::Keypair;
    use crate::data_structures::{AlarmDetail, AlarmType};

    use super::*;

    fn test_generate_rand_key() -> SigningKey<Sha256> {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        // generate random signing key
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        SigningKey::<Sha256>::new(private_key)
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = test_generate_rand_key();
        // Tests the signing and verification of messages
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
    fn test_data_encode_decode() {
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
    fn test_reject_tampered_payload() {
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
    #[tokio::test]
    async fn test_send_activation_command() {
        let signing_key = test_generate_rand_key();
        let asp_inst = ASP::new(&signing_key, "Unit Tests").await.unwrap();
        asp_inst.broadcast(AlarmType::Intruder, vec!(AlarmDetail::Lockdown)).await.unwrap()
    }

    #[tokio::test]
    async fn test_parse_raw_packet() {
        let signing_key = test_generate_rand_key();
        let asp_inst = ASP::new(&signing_key, "Unit Tests").await.unwrap();
        asp_inst.broadcast(AlarmType::Intruder, vec!(AlarmDetail::Lockdown)).await.unwrap()
    }

    #[test]
    fn test_asp_message_formatting() {
        // Arrange
        let mut asp_message = ASPMessage::new("John Doe", vec![AlarmDetail::Lockdown], AlarmType::Intruder);
        // override message ID to a predictable value
        asp_message.id = 123;
        // Act
        let formatted_string = format!("{}", asp_message);
    
        // Assert
        assert_eq!(formatted_string, "(Alarm ID 123 of type Intruder, activated by: John Doe with details [Lockdown])");
    }
    #[tokio::test]
    async fn test_asp_object_clone() {
        let signing_key = test_generate_rand_key();
        let asp_inst = ASP::new(&signing_key, "Unit Tests").await.unwrap();
        let asp_inst_ii = asp_inst.clone();
        assert_eq!(asp_inst.pretty_name, asp_inst_ii.pretty_name);
        assert_eq!(asp_inst.socket.local_addr().unwrap(), asp_inst_ii.socket.local_addr().unwrap());
        assert!(asp_inst_ii.broadcast(AlarmType::Countermand, vec!()).await.is_ok());
    }
    

}

