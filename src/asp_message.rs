use std::{fmt, io, time};
use std::fmt::Display;
use std::io::Error;

use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, Verifier};

use crate::data_err;
use crate::data_structures::{AlarmDetail, AlarmType};

#[derive(Debug, Clone)]
pub struct ASPMessage {
    pub activator_name: String,
    pub alarm_details: Vec<AlarmDetail>,
    pub alarm_type: AlarmType,
    pub signature: Option<Signature>,
    pub(crate) raw: Option<[u8; 41]>,
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
            alarm_type = AlarmType::Fire
        }
        else if (alarm_code & 0x40) !=0 {
            alarm_type = AlarmType::Intruder
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
            signature: Some(Signature::try_from(sigarray)
                .map_err(|err|data_err(format!("Could not parse signature: {}", err.to_string()).as_str()))?),
            raw: Some(message_vec[0 .. 42].try_into()
                .map_err(|_err|data_err("Payload anomaly"))?)
        })
    }
}

impl TryInto<[u8; 41]> for ASPMessage {
    type Error = Error;
    fn try_into(self) -> Result<[u8; 41], Error> {
        let mut out: Vec<u8> = vec!();
        // add name to payload
        out.extend_from_slice(self.activator_name.as_bytes());
        // add alarm detail byte to payload
        out.push(build_alarm_byte(self.alarm_type, self.alarm_details));
        // calculate current system time (UNIX Timestamp)
        let ts = time::SystemTime::now().duration_since(time::UNIX_EPOCH)
            .map_err(|_err|data_err("Invalid Timestamp"))?;
        // add timestamp to payload
        out.extend_from_slice(ts.as_secs().to_be_bytes().as_slice());
        <[u8; 41]>::try_from(out.as_slice()).map_err(|err|data_err(
            format!("Conversion failed: {}", err).as_str()))
    }
}

impl Display for ASPMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(Alarm type {:?}, activated by: {} with details {:?})",
               self.alarm_type, self.activator_name, self.alarm_details)
    }
}

impl ASPMessage{
    pub fn verify_sig(&self, pubkey: VerifyingKey<Sha256>) -> Result<(), Error> {
        let sig: &Signature;
        let raw: &[u8];
        match &self.signature {
            Some(s) => sig = s,
            None => return Err(data_err("Signature not present!"))
        }
        match &self.raw {
            Some(r) => raw = r,
            None => return Err(data_err("Raw data not present!"))
        }
        // safe to unwrap since we just checked the data is there
        pubkey.verify(raw, sig)
            .map_err(|err|data_err(format!("Signature Invalid! {}", err.to_string()).as_str()))?;
        Ok(())
    }
    pub fn sign(&self, signing_key: SigningKey<Sha256>) -> Result<Signature, Error> {
        let mut rng = rand::thread_rng();
        println!("checkpoint");
        let sclone = self.clone();
        let body: [u8; 41] = sclone.try_into()?;
        let signature = signing_key.sign_with_rng(&mut rng, body.as_slice());
        Ok(signature)
    }
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

fn build_alarm_byte(atype: AlarmType, details: Vec<AlarmDetail>) -> u8{
    let mut retn: u8 = 0;
    if atype == AlarmType::Intruder {
        retn |= 0x40;
    }
    else {
        retn |= 0x80;
    }
    for deet in details {
        match deet {
            AlarmDetail::Silent => retn |= 0x1,
            AlarmDetail::Browser => retn |= 0x2,
            AlarmDetail::Lockdown => retn |= 0x4,
            AlarmDetail::Evacuate => retn |= 0x8
        }
    }
    retn
}