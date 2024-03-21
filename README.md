# Alarm Signaling Protocol - Rust implementation

This is the implementation of the alarm signaling protocol in Rust for the Housy Alert system, built on top of UDP. The payload is as follows:

|------32 Bytes------|---1 Byte---|----4 Bytes----|---------------256 Bytes---------------|
|---Activator Name---|-Alarm Code-|UNIX  Timestamp|---------------Signature---------------|

(Diagram is not to scale)

