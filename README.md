
# SOCP v1.3 – Minimal but Spec‑Complete (Educational)

This repo implements the **required** features of SOCP v1.3 in a compact, heavily‑commented form:

- **Crypto:** RSA‑4096, OAEP(SHA‑256) encryption, PSS(SHA‑256) signatures, base64url (no padding).
- **Transport:** WebSocket; one JSON envelope per WS message; canonical payload signing.
- **Server↔Server:** Bootstrap (HELLO_JOIN / WELCOME / ANNOUNCE), Presence Gossip (ADVERTISE/REMOVE),
  Forwarded Delivery (SERVER_DELIVER), Heartbeats + 45s timeout.
- **User↔Server:** USER_HELLO, E2EE Direct Message, Public Channel (join, key share, broadcast),
  File Transfer (manifest/chunk/end), ACK/ERROR.
- **Routing:** Authoritative 3‑step algorithm with loop suppression.
- **DB:** Persistent `users`, `groups`, `group_members` as required.

> This is an instructional reference. It favours clarity over performance.

## Contact Details of Group Members if Required:
- Tony Le <tony.le@student.adelaide.edu.au>
- Sam Lovat <samuel.lovat@student.adelaide.edu.au>
- Kemal Kiverić <kemal.kiveric@student.adelaide.edu.au>
- Ayii Madut <ayii.madut@student.adelaide.edu.au>
- Rajkarthick Raju <rajkarthick.raju@student.adelaide.edu.au>

## Quickstart (three pinned servers on localhost)

1. **Create venv & install deps**

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Generate transport keys** – run each server once (in its own terminal) so `server_key.json` is created. Use separate key files to avoid overwriting:

   ```bash
   # Terminal A
   SOCP_SERVER_KEYFILE=server_key_srv-a.json python server.py --server-id srv-a --port 8765

   # Terminal B
   SOCP_SERVER_KEYFILE=server_key_srv-b.json python server.py --server-id srv-b --port 8766

   # Terminal C
   SOCP_SERVER_KEYFILE=server_key_srv-c.json python server.py --server-id srv-c --port 8767
   ```

   Stop each server after it prints the listening banner (`Ctrl+C`). Extract the base64url public key from each key file:

   ```bash
   python -c "import json; print(json.load(open('server_key_srv-a.json'))['pub_spki_b64u'])"  # repeat for b/c
   ```

3. **Populate introducer pins** – run the helper to inject the pubkeys and show ready-to-use bootstrap strings:

   ```bash
   python3 tools/update_pins.py --config config.yaml \
     --key ws://127.0.0.1:8765=server_key_srv-a.json \
     --key ws://127.0.0.1:8766=server_key_srv-b.json \
     --key ws://127.0.0.1:8767=server_key_srv-c.json
   ```

   The script rewrites `config.yaml` in place and prints matching `--bootstrap` fragments; if a URL is missing from the introducer list, it will warn so you can adjust the config.

4. **Run the three servers** – re-open the terminals and launch permanently, pointing each at a distinct DB/key file and reusing the pinned bootstrap list (order doesn’t matter):

   ```bash
   # Terminal A
   SOCP_DB=socp-a.db SOCP_SERVER_KEYFILE=server_key_srv-a.json \
     python server.py --server-id srv-a --port 8765 \
     --bootstrap ws://127.0.0.1:8766#<srv-b pub> ws://127.0.0.1:8767#<srv-c pub>

   # Terminal B
   SOCP_DB=socp-b.db SOCP_SERVER_KEYFILE=server_key_srv-b.json \
     python server.py --server-id srv-b --port 8766 \
     --bootstrap ws://127.0.0.1:8765#<srv-a pub> ws://127.0.0.1:8767#<srv-c pub>

   # Terminal C
   SOCP_DB=socp-c.db SOCP_SERVER_KEYFILE=server_key_srv-c.json \
     python server.py --server-id srv-c --port 8767 \
     --bootstrap ws://127.0.0.1:8765#<srv-a pub> ws://127.0.0.1:8766#<srv-b pub>
   ```

5. **Connect clients** – from two extra terminals, interact with the mesh:

   ```bash
   # Terminal D (Alice)
   python client.py --url ws://127.0.0.1:8765
   > /register alice passw0rd
   > /login alice passw0rd
   > /all hello mesh!

   # Terminal E (Bob)
   python client.py --url ws://127.0.0.1:8766
   > /register bob s3cret
   > /login bob s3cret
   > /tell alice hello across servers!
   > /file alice ./README.md
   ```

Each `/all` broadcast is encrypted per-recipient using RSA-OAEP, so servers simply relay signatures without ever decrypting user payloads.

**Security model (demo):** The client decrypts private keys locally using a password. For convenience,
the demo server returns the caller’s own encrypted private key blob at login so the client can decrypt
locally—this mirrors “directory returns your blob” in the spec’s recommended model.


---

## SOCP v1.3 Compliance Checklist (spec → code)

- **RSA‑4096, OAEP(SHA‑256), PSS(SHA‑256), base64url** → `crypto.py` (all helpers)
- **Canonical JSON payload + transport signatures (server↔server)** → `envelope.py` (`transport_sign/verify`), used in `server.py`
- **Server↔Server mesh**  
  - HELLO_JOIN/WELCOME/HELLO_LINK handshake with pinned introducers → `server.py: process_server_hello_join`, `connect_to_peer()`  
  - Bootstrap/announce → `server.py: connect_to_peer()`, `SERVER_ANNOUNCE` handling  
  - Presence gossip → `USER_ADVERTISE` / `USER_REMOVE` in `server.py`  
  - Forwarded Delivery → `SERVER_DELIVER` path in `server.py`  
  - Heartbeats (15s) + pruning → `heartbeat_task()` in `server.py`
- **Routing & loop‑suppression** → `server.py` (`deliver_dm_or_forward` + `ReplayCache`), `envelope.payload_hash16()`
- **Persistent DB** (`users`, `groups`, `group_members`) → `schema.sql` + `directory.py:init_db()`
- **Public channel**  
  - Ensure channel exists → `directory.init_db()`  
  - Membership gossip & joins → `server.py: broadcast_public_channel_add/updated`  
  - Broadcast (`/all`) → client RSA-OAEP encrypts per member; server verifies signatures and routes signed `MSG_PUBLIC_CHANNEL`
- **User protocol**  
  - USER_HELLO / Registration / Login → `server.py` (`USER_HELLO`, `USER_REGISTER`, `USER_LOGIN`), client mirrors  
  - E2EE DMs → client (`/tell`) OAEP encrypt + `content_sig`; server routes blind; client decrypts  
  - File transfer → client `/file` sends `FILE_START/CHUNK/END`; server routes like DMs
- **Client commands** → `client.py`: `/list`, `/tell`, `/all`, `/file`
- **README + run instructions** → this file

### Limitations (intentional, for compactness)
- Assignment-style PAKE verifier is emulated with scrypt; real PAKE is out of scope in this demo.
- Server IDs for peers are simplified to URLs; pinning can be added to `server_addrs` easily.
