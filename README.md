# Alarm Signaling Protocol - Rust implementation

[![Rust tests](https://github.com/HousyAlert-Block-3/ASP-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/HousyAlert-Block-3/ASP-rs/actions/workflows/rust.yml)


This is the implementation of the alarm signaling protocol in Rust for the Housy Alert system, built on top of UDP. The payload is as follows:

| Field           | Size (Bytes) |
|-----------------|--------------|
| Activator Name  | 32           |
| Alarm Code      | 1            |
| UNIX  Timestamp | 8            |
| Signature       | 256          |


(Diagram is not to scale)

This protocol's byte order is big endian.

The Alarm Type byte stores a series of characteristics 
of the signaled alarm as a series of booleans where 1 indicates
that the aspect is true about the alarm condition.

| Bit | Meaning  | Notes                                    |
|-----|----------|------------------------------------------|
| 0   | Silent   | Only notify select staff                 |
| 1   | Browser  | Enable browser extension alerting        |
| 2   | Lockdown | Indicates a shelter in place instruction |
| 3   | Evacuate |                                          |
| 4   | Reserved | Reserved for future use                  |
| 5   | Reserved | Reserved for future use                  |
| 6   | Intruder |                                          |
| 7   | Fire     |                                          |
