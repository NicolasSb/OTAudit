# Passive audit of industrial traffic

**Engagement.** Passive audit - Site A control network
**Authorisation.** J. Martin, maintenance manager, reference BC-2026-014
**Authorised window.** 2023-11-14T20:00:00+00:00 to 2023-11-15T02:00:00+00:00
**Report generated.** 2026-10-27T17:23:07+00:00

Capture taken on the mirrored port of the control switch, no injection. Supervision and engineering VLANs only.


## Capture

| | |
| --- | --- |
| File | `samples/demo.pcap` |
| First packet | 2023-11-14T22:13:20+00:00 |
| Last packet | 2023-11-14T22:14:02.089000+00:00 |
| Duration | 42 s |
| TCP segments | 289 |
| Industrial frames | 287 |
| Truncated records | 0 |
| Stream gaps | 0 |
| Within authorised window | yes |

## Devices

| Address | Role | Protocol | Unit IDs | Identification | Other services | Scope |
| --- | --- | --- | --- | --- | --- | --- |
| 10.42.7.10 | client | - | - | - | - | in |
| 10.42.7.11 | client | - | - | - | - | in |
| 10.42.7.20 | server | modbus | 1 | - | 23 | in |
| 10.42.7.21 | server | modbus | 1 | TM241CE40R / 5.1.9.9 / Schneider Electric | - | in |
| 10.42.7.22 | server | modbus | 1 | - | - | in |
| 10.42.7.30 | server | s7comm | - | 6ES7 214-1AG40-0XB0 / CPU 1214C DC/DC/DC / LINE2_CPU | - | in |
| 10.42.7.40 | server | opcua | - | Line 3 gateway / urn:line3:gateway / urn:vendor:uagateway | - | in |
| 10.42.9.80 | client | - | - | - | - | outside |

### OPC UA endpoints

As the servers described them in answer to GetEndpoints.

| Server | Endpoint | Security mode | Security policy | User tokens |
| --- | --- | --- | --- | --- |
| 10.42.7.40 | `opc.tcp://10.42.7.40:4840` | None | None | anonymous, username |
| 10.42.7.40 | `opc.tcp://10.42.7.40:4840` | Sign | Basic128Rsa15 | username |
| 10.42.7.40 | `opc.tcp://10.42.7.40:4840` | SignAndEncrypt | Basic256Sha256 | username, certificate |

## Exchanges

| Client | Server | Protocol | Requests | Responses | Writes | Exceptions | Mean interval | Unanswered | Response time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10.42.7.10 | 10.42.7.20:502 | modbus | 41 | 41 | 1 | 0 | 750 ms | 0 | 4.0 ms (max 5.0) |
| 10.42.9.80 | 10.42.7.20:502 | modbus | 1 | 1 | 1 | 0 | - | 0 | 6.0 ms (max 6.0) |
| 10.42.7.10 | 10.42.7.21:502 | modbus | 41 | 41 | 0 | 0 | 782 ms | 0 | 4.1 ms (max 8.0) |
| 10.42.7.10 | 10.42.7.22:502 | modbus | 40 | 40 | 0 | 20 | 750 ms | 0 | 4.0 ms (max 4.0) |
| 10.42.7.11 | 10.42.7.30:102 | s7comm | 3 | 4 | 1 | 0 | 415 ms | 0 | 16.7 ms (max 20.0) |
| 10.42.7.10 | 10.42.7.40:4840 | opcua | 11 | 11 | 1 | 0 | 510 ms | 0 | 10.0 ms (max 10.0) |
| 10.42.7.11 | 10.42.7.40:4840 | opcua | 6 | 6 | 0 | 0 | 510 ms | 0 | 10.0 ms (max 10.0) |

- `10.42.7.10 -> 10.42.7.20:502`: read holding registers (40), write multiple registers (1)
  - written: unit 1 holding registers 100
- `10.42.9.80 -> 10.42.7.20:502`: write single register (1)
  - written: unit 1 holding registers 100
- `10.42.7.10 -> 10.42.7.21:502`: encapsulated interface transport (1), read holding registers (40)
- `10.42.7.10 -> 10.42.7.22:502`: read holding registers (40)
- `10.42.7.11 -> 10.42.7.30:102`: cpu services (1), setup communication (1), write variable (1)
- `10.42.7.10 -> 10.42.7.40:4840`: activate session (1), create session (1), get endpoints (1), hello (1), open secure channel (1), read (5), write (1)
  - nodes written: ns=2;s=Line3.Setpoint
  - secure channels: None (1)
  - session users: username (1)
- `10.42.7.11 -> 10.42.7.40:4840`: encrypted message (4), hello (1), open secure channel (1)
  - secure channels: Basic256Sha256 (1)

## Findings

### OT-003 - Several hosts write to the same device

**Severity.** high
**Assets.** 10.42.7.20
**References.** CR 2.1 / Mesure 12 (gestion des droits)

Observed:

- 10.42.7.20 written by 10.42.7.10, 10.42.9.80
- 10.42.7.10 and 10.42.9.80 both write unit 1 holding registers 100

Identify each writer and the reason it exists. A second master is usually a maintenance laptop or a supervision station left connected after commissioning; concurrent writes to the same registers also cause process incidents that are hard to attribute.

### OT-008 - Legacy management services reachable on the control segment

**Severity.** high
**Assets.** 10.42.7.20
**References.** CR 1.1 / CR 4.1 / CR 7.6 / Mesure 14 (durcissement) / Mesure 19 (protocoles)

Observed:

- 10.42.7.20: telnet/23

Disable the services that are not required for operation. Where an HMI or a gateway genuinely needs them, restrict the source addresses and stop using the ones that carry credentials in clear.

### OT-017 - OPC UA passwords sent without encryption

**Severity.** high
**Assets.** 10.42.7.40
**References.** CR 1.5 / CR 4.1 / Mesure 12 (gestion des droits) / Mesure 19 (protocoles)

Observed:

- 10.42.7.10 -> 10.42.7.40:4840 - password of 'supervision' readable in the capture

The password is in the capture file itself: change it, and handle the capture as a credential until it is deleted. Then make sure passwords leave the client encrypted, either on a SignAndEncrypt channel or through a user token policy with its own security policy.

### OT-001 - Control traffic carried without authentication or integrity protection

**Severity.** medium
**Assets.** 10.42.7.20, 10.42.7.21, 10.42.7.22, 10.42.7.30
**References.** CR 3.1 / CR 4.1 / Mesure 15 (cloisonnement) / Mesure 19 (protocoles)

Observed:

- modbus observed in clear text on the mirrored segment
- s7comm observed in clear text on the mirrored segment

Neither Modbus/TCP nor S7comm carries authentication. Compensate at the network layer: dedicated VLAN, filtering between the control segment and everything else, and no route from office IT to port 502 or 102.

### OT-002 - Write operations observed on the control network

**Severity.** medium
**Assets.** 10.42.7.20, 10.42.7.30, 10.42.7.40
**References.** CR 1.2 / CR 2.1 / Mesure 12 (gestion des droits)

Observed:

- 10.42.7.10 -> 10.42.7.20:502 - 1 write requests (unit 1 holding registers 100)
- 10.42.9.80 -> 10.42.7.20:502 - 1 write requests (unit 1 holding registers 100)
- 10.42.7.11 -> 10.42.7.30:102 - 1 write requests
- 10.42.7.10 -> 10.42.7.40:4840 - 1 write requests (ns=2;s=Line3.Setpoint)

Confirm with the operator that each writing host is a legitimate controller. Any host able to reach port 102 or 502 or 4840 can issue the same requests, so the control list is whatever the firewall allows, not what the application intends.

### OT-005 - Industrial hosts seen outside the declared target ranges

**Severity.** medium
**Assets.** 10.42.9.80
**References.** CR 1.2 / Mesure 1 (cartographie)

Observed:

- 10.42.9.80 (client) not covered by scope targets

The asset inventory used to write the scope does not match the traffic. Reconcile before drawing any conclusion from the rest of this report: an audit that missed a device also missed its exposure.

### OT-014 - OPC UA used without signing or encryption

**Severity.** medium
**Assets.** 10.42.7.40
**References.** CR 3.1 / CR 4.1 / Mesure 19 (protocoles)

Observed:

- 10.42.7.10 -> 10.42.7.40:4840 - 8 requests on a secure channel with security policy None
- 10.42.7.40 offers opc.tcp://10.42.7.40:4840 with security mode None

OPC UA can sign and encrypt every message; these exchanges did neither, and are as open to reading and tampering as Modbus. Move the clients to SignAndEncrypt endpoints with Basic256Sha256 or a newer policy, then remove the None endpoint from the server. Discovery over policy None (GetEndpoints, FindServers) is what the specification expects and is not counted here.

### OT-016 - OPC UA sessions without user authentication

**Severity.** medium
**Assets.** 10.42.7.40
**References.** CR 1.1 / CR 2.1 / Mesure 12 (gestion des droits)

Observed:

- 10.42.7.40 accepts anonymous users on opc.tcp://10.42.7.40:4840

An anonymous session gets whatever the server grants to everyone, which on many servers includes writing. Disable the anonymous token, or restrict the anonymous role to reading, and give each client its own user or certificate.

### OT-007 - Recurrent protocol exceptions

**Severity.** low
**Assets.** 10.42.7.22
**References.** CR 7.2 / Mesure 17 (journalisation)

Observed:

- 10.42.7.10 -> 10.42.7.22:502 - 50% of responses are exceptions (illegal data address on read holding registers x20)

Persistent exceptions usually mean a supervision template polling addresses that no longer exist. Harmless in itself, it consumes cycles on the device and hides genuine faults in the logs.

### OT-009 - Devices disclose model and firmware to any peer

**Severity.** low
**Assets.** 10.42.7.21, 10.42.7.30, 10.42.7.40
**References.** CR 1.2 / Mesure 1 (cartographie) / Mesure 20 (veille vulnérabilités)

Observed:

- 10.42.7.21: product=TM241CE40R, revision=5.1.9.9, vendor=Schneider Electric
- 10.42.7.30: article_number=6ES7 214-1AG40-0XB0, module_type=CPU 1214C DC/DC/DC, plc_name=LINE2_CPU
- 10.42.7.40: application_name=Line 3 gateway, application_uri=urn:line3:gateway, product_uri=urn:vendor:uagateway

Identification cannot be turned off on these protocols, and it is useful to you as much as to an attacker. Use it: match each order number and firmware version against the CISA ICS advisories and the vendor bulletins, and record the result in the asset inventory.

### OT-015 - Deprecated OPC UA security policies

**Severity.** low
**Assets.** 10.42.7.40
**References.** CR 4.3 / Mesure 19 (protocoles)

Observed:

- 10.42.7.40 offers opc.tcp://10.42.7.40:4840 with Basic128Rsa15

Basic128Rsa15 and Basic256 rely on SHA-1 and were deprecated by the OPC Foundation. Disable them on the server once every client supports Basic256Sha256 or one of the Aes policies.


## Method and limits

The capture was read offline. No frame was emitted towards the audited network,
so nothing in this report required interaction with a device in production.

What this implies for the reader: the report describes traffic seen during the
window above, and nothing else. A device that was silent does not appear. A
service that was not used does not appear. Absence of a finding is absence of
evidence, not evidence of absence, and the sections above should be read
alongside the configuration review and the interviews, never on their own.
