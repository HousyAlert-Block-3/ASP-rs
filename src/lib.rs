mod data_structures;

use std::fmt::{Display};
use std::{fmt, io};
use std::io::{Error, Read};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Digest, Sha256};
use std::net::{UdpSocket, SocketAddr, IpAddr};
use crate::AlarmType::{Fire, Intruder};
use std::time;

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

#[derive(Debug)]
pub struct ASPMessage {
    activator_name: String,
    alarm_details: Vec<AlarmDetail>,
    alarm_type: AlarmType,
    signature: Signature,
    raw: [u8; 41],
}

impl TryFrom<&[u8]> for ASPMessage {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let message_vec = value.to_vec();
        if message_vec.len() != 297 {
            return Err(data_err("Incorrect message length"));
        }
        let namevec: Vec<u8> = message_vec[0..32].to_vec();
        let alarm_code = message_vec[32];
        let alarm_type: AlarmType;
        if (alarm_code & 0x80) !=0 {
            alarm_type = Fire
        }
        else if (alarm_code & 0x40) !=0 {
            alarm_type = Intruder
        }
        else { return Err(data_err("No alarm type specified!")); }
        // Get timestamp from payload, convert to u64
        let timebytes: [u8; 8] = message_vec[33 .. 42].try_into()
            .map_err(|_err|data_err("Invalid Timestamp"))?;
        let timestamp = time::Duration::from_secs(u64::from_be_bytes(timebytes));
        let mesg_time = time::UNIX_EPOCH + timestamp;
        let elapsed = time::SystemTime::now().duration_since(mesg_time)
            .map_err(|_err|Error::new(io::ErrorKind::InvalidInput,"message from the future!"))?;
        if elapsed.as_secs() > 60 {
            return Err(Error::new(io::ErrorKind::InvalidInput,
            format!("Message too old! Received {}s ago.", elapsed.as_secs())));
        }
        let sigarray = &message_vec[38 ..];
        Ok(ASPMessage {
            activator_name: String::from_utf8(namevec)
                .map_err(|_err|Error::new(io::ErrorKind::InvalidData,"Bad name data"))?
                .chars().filter(|c| c.is_alphanumeric()).collect(),
            alarm_details: alarm_byte_to_vec(alarm_code),
            alarm_type,
            signature: Signature::try_from(sigarray)
                .map_err(|err|data_err(format!("Could not parse signature: {}", err.to_string()).as_str()))?,
            raw: message_vec[0 .. 42].try_into()
                .map_err(|_err|data_err("Payload anomaly"))?
        })
    }
}

impl Display for ASPMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "(Alarm type {:?}, activated by: {} with details {:?})", 
        self.alarm_type, self.activator_name, self.alarm_details)
    }
}

impl ASPMessage{
    fn verify_sig(&self, pubkey: VerifyingKey<Sha256>) -> Result<(), Error> {
        pubkey.verify(&self.raw, &self.signature)
            .map_err(|err|data_err(format!("Signature Invalid! {}", err.to_string()).as_str()))?;
        Ok(())
    }
}

fn data_err(msg: &str) -> Error {
    Error::new(io::ErrorKind::InvalidData, msg)
}

fn alarm_byte_to_vec(byte: u8) -> Vec<AlarmDetail> {
    let mut retn: Vec<AlarmDetail> = vec!();
    // mfw rust doesn't have implicit casts to bool
    if (byte & 0x1) != 0 {
        retn.push(AlarmDetail::Silent);
    }
    if (byte & 0x2) != 0 {
        retn.push(AlarmDetail::Browser);
    }
    if (byte & 0x4) != 0 {
        retn.push(AlarmDetail::Lockdown);
    }
    if (byte & 0x8) != 0 {
        retn.push(AlarmDetail::Evacuate);
    }
    retn
}

#[derive(Debug)]
enum AlarmDetail {
    Silent,
    Browser,
    Lockdown,
    Evacuate,
}

#[derive(Debug)]
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
