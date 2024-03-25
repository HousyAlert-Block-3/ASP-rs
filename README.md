# Alarm Signaling Protocol - Rust implementation

[![Rust tests](https://github.com/HousyAlert-Block-3/ASP-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/HousyAlert-Block-3/ASP-rs/actions/workflows/rust.yml)


This is the implementation of the alarm signaling protocol in Rust for the Housy Alert system, built on top of UDP. 
## Overview / Design Goals

This protocol was designed 

## Usage

Interaction with ASP is done through an instance of the `ASP` struct.
This struct must be initialized with a signing key of type `rsa::pkcs1v15::SigningKey<Sha256>`
and the human-readable name of the instance. 

The `try_receive()` method of ASP returns an instance of `ASPMessage` wrapped in an option wrapped in a result.
This double-wrapping is necessary to differentiate between an error and no message being received as the
function is nonblocking. 

```rust
use ASP_rs::{ASP, asp_message::ASPMessage, data_structures::{AlarmType, AlarmDetail}};
fn main() {
    let asp_inst = ASP::new(&signing_key, "Minimal Implementation").unwrap();
    asp_inst.broadcast(AlarmType::Intruder, vec!(AlarmDetail::Lockdown)).unwrap();
    let recieved_message: ASPMessage = inst.try_receive().unwrap().unwrap();
}
```

## Protocol Details

The payload is as follows:

| Field          | Size (Bytes) |
|----------------|--------------|
| Activator Name | 32           |
| Alarm Code     | 1            |
| ID             | 4            |
| Signature      | 256          |

This protocol's byte order is big endian.

The Alarm Type byte stores a series of characteristics 
of the signaled alarm as a series of booleans where 1 indicates
that the aspect is true about the alarm condition.

| Bit | Meaning     | Notes                                    |
|-----|-------------|------------------------------------------|
| 0   | Silent      | Only notify select staff                 |
| 1   | Browser     | Enable browser extension alerting        |
| 2   | Lockdown    | Indicates a shelter in place instruction |
| 3   | Evacuate    |                                          |
| 4   | Reserved    | Reserved for future use                  |
| 5   | Fire        |                                          |
| 6   | Intruder    |                                          |
| 7   | Countermand | Signals that alarm condition is over     |
