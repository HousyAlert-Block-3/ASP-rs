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
    Fire
}