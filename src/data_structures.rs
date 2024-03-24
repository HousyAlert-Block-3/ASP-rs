use std::io;

#[derive(Debug, PartialEq, Clone)]
pub enum AlarmDetail {
    Silent,
    Browser,
    Lockdown,
    Evacuate,
}


#[derive(Debug, PartialEq, Clone)]
pub enum AlarmType {
    Intruder,
    Fire,
    Countermand
}

impl Into<u8> for &AlarmType {
    fn into(self) -> u8 {
        match *self {
            AlarmType::Countermand => 0x80,
            AlarmType::Intruder => 0x40,
            AlarmType::Fire => 0x20
        }
    }
}

impl TryFrom<&u8> for AlarmType {
    type Error = io::Error;
    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match *value & 0xF0 {
            0x80 => Ok(AlarmType::Countermand),
            0x40 => Ok(AlarmType::Intruder),
            0x20 => Ok(AlarmType::Fire),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Bad Alarm Type"))
        }
    }
}