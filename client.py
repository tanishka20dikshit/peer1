
"""
SOCP v1.3 Client (educational). Implements:
- /register, /login, /list, /tell, /all, /file
- E2EE DM: RSA-OAEP ciphertext + content_sig
- Public channel: receives channel membership snapshots and RSA-wrapped shares; /all fan-outs
  RSA-OAEP ciphertexts per recipient (integrity via RSASSA-PSS content signatures).
- File transfer: sends FILE_START / FILE_CHUNK / FILE_END (DM mode), encrypted per chunk.
"""
from __future__ import annotations
import argparse, asyncio, websockets, json, shlex, sys, os, math
from typing import Optional, Dict
from crypto import (
    b64u,
    b64u_decode,
    rsa_oaep_encrypt,
    rsa_oaep_decrypt,
    sign_pss_sha256,
    verify_pss_sha256,
    export_public_spki_b64u,
    load_public_spki_b64u,
)
from cli_crypto import generate_and_encrypt, decrypt_private_key
from utils import now_ms

def sha256(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()

class Client:
    def __init__(self, url: str):
        self.url = url
        self.user_id: Optional[str] = None
        self.password: Optional[str] = None
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.priv = None  # RSA private key object (in-memory after login)
        self.pub_b64u: Optional[str] = None
        # Directory cache
        self.pubkeys: Dict[str, str] = {}  # user_id -> spki b64u
        # Public channel state
        self.public_members: Dict[str, str] = {}  # member_id -> metadata placeholder
        self.public_version: int = 0

    def _sign_public_channel(self, ciphertext: bytes, ts: int) -> bytes:
        assert self.priv is not None
        data = b"".join([ciphertext, self.user_id.encode(), str(ts).encode()])
        return sign_pss_sha256(self.priv, data)

    @staticmethod
    def _verify_public_channel(sender_pub_b64u: str, ciphertext: bytes, content_sig_b64u: str, sender: str, ts: int) -> bool:
        try:
            pub = load_public_spki_b64u(sender_pub_b64u)
            data = b"".join([ciphertext, sender.encode(), str(ts).encode()])
            return verify_pss_sha256(pub, b64u_decode(content_sig_b64u), data)
        except Exception:
            return False

    async def connect(self):
        self.ws = await websockets.connect(self.url, ping_interval=15, ping_timeout=20)

    async def send(self, obj):
        await self.ws.send(json.dumps(obj))

    async def recv_loop(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "USER_DELIVER":
                    # E2EE DM delivery: decrypt ciphertext with our private key
                    p = msg.get("payload", {})
                    ct = b64u_decode(p.get("ciphertext",""))
                    sender = p.get("sender")
                    sender_pub = p.get("sender_pub")
                    ts = p.get("ts") or msg.get("ts")
                    if self.priv is None:
                        print("\n[warn] no private key in memory; cannot decrypt DM")
                    else:
                        try:
                            pt = rsa_oaep_decrypt(self.priv, ct)
                            sig_status = ""
                            if sender_pub and p.get("content_sig") and self.user_id:
                                try:
                                    pub = load_public_spki_b64u(sender_pub)
                                    tuple_bytes = b"".join([
                                        ct,
                                        sender.encode(),
                                        self.user_id.encode(),
                                        str(ts).encode(),
                                    ])
                                    ok = verify_pss_sha256(pub, b64u_decode(p.get("content_sig", "")), tuple_bytes)
                                    sig_status = " (sig ok)" if ok else " (sig FAIL)"
                                except Exception:
                                    sig_status = " (sig FAIL)"
                            print(f"\n[DM from {sender}] {pt.decode('utf-8', 'ignore')}{sig_status}")
                        except Exception as e:
                            print(f"\n[DM decrypt error] {e}")
                    print("> ", end="", flush=True)

                elif t == "LIST_RESPONSE":
                    # cache pubkeys (if provided)
                    for u in msg.get("users", []):
                        if "pubkey" in u and u["pubkey"]:
                            self.pubkeys[u["user_id"]] = u["pubkey"]
                            if self.user_id and u["user_id"] == self.user_id and not self.pub_b64u:
                                self.pub_b64u = u["pubkey"]
                    print(f"\n{msg}")
                    print("> ", end="", flush=True)

                elif t == "USER_ADDED":
                    # Automatically update client's pubkey cache when new user joins
                    payload = msg.get("payload", {})
                    user_id = payload.get("user_id")
                    pubkey = payload.get("pubkey")
                    if user_id and pubkey:
                        self.pubkeys[user_id] = pubkey
                        print(f"\n[user added] {user_id} is now available for messaging")
                    print("> ", end="", flush=True)

                elif t == "USER_REMOVED":
                    # Automatically remove user from client's pubkey cache when user leaves
                    payload = msg.get("payload", {})
                    user_id = payload.get("user_id")
                    if user_id and user_id in self.pubkeys:
                        del self.pubkeys[user_id]
                        print(f"\n[user removed] {user_id} is no longer available")
                    print("> ", end="", flush=True)

                elif t == "PUBLIC_CHANNEL_KEY_SHARE":
                    # Track membership hints; actual key material handled by clients via pubkeys.
                    p = msg.get("payload", {})
                    wraps = p.get("shares", [])
                    for w in wraps:
                        member = w.get("member")
                        if member:
                            self.public_members.setdefault(member, "")
                    print("> ", end="", flush=True)

                elif t == "PUBLIC_CHANNEL_SNAPSHOT":
                    snap = msg.get("payload", {})
                    members = snap.get("members", [])
                    self.public_version = snap.get("version", self.public_version)
                    self.public_members = {m: self.public_members.get(m, "") for m in members}
                    print(f"\n[public] membership v{self.public_version}: {members}")
                    print("> ", end="", flush=True)

                elif t in ("MSG_PUBLIC_CHANNEL", "MSG_PUBLIC_CHANNEL_DELIVER"):
                    p = msg.get("payload", {})
                    ciphertext_b64u = p.get("ciphertext", "")
                    sender = p.get("sender")
                    sender_pub = p.get("sender_pub")
                    ts = p.get("ts") or msg.get("ts")
                    try:
                        ct = b64u_decode(ciphertext_b64u)
                        if self.priv is None:
                            raise ValueError("no private key loaded")
                        pt = rsa_oaep_decrypt(self.priv, ct)
                        verified = False
                        if sender_pub and p.get("content_sig"):
                            verified = self._verify_public_channel(sender_pub, ct, p.get("content_sig", ""), sender, ts)
                        prefix = "[public]"
                        body = pt.decode("utf-8", "ignore")
                        status = " (sig ok)" if verified else " (sig FAIL)"
                        print(f"\n{prefix} {sender}: {body}{status}")
                    except Exception as e:
                        print(f"\n[public decrypt error] {e}")
                    print("> ", end="", flush=True)

                elif t == "USER_LOGGED_IN":
                    payload = msg.get("payload", {})
                    self.user_id = payload.get("user_id", self.user_id)
                    blob = payload.get("privkey_store")
                    if blob and self.password:
                        try:
                            self.priv = decrypt_private_key(blob, self.password)
                            self.pub_b64u = export_public_spki_b64u(self.priv)
                            if self.user_id:
                                self.pubkeys[self.user_id] = self.pub_b64u
                            print(f"\n[login] unlocked key for {self.user_id}")
                        except Exception as e:
                            print(f"\n[login] private key decrypt failed: {e}")
                    print("> ", end="", flush=True)

                elif t == "USER_HELLO_ACK":
                    print("\n[server] hello acknowledged")
                    print("> ", end="", flush=True)

                elif t == "ERROR":
                    payload = msg.get("payload", {})
                    code = payload.get("code", "ERROR")
                    detail = payload.get("detail", "")
                    print(f"\n[error] {code} {detail}".rstrip())
                    print("> ", end="", flush=True)

                else:
                    print(f"\n{msg}")
                    print("> ", end="", flush=True)
        except websockets.ConnectionClosed:
            print("\n[disconnected]")

    async def cmd_register(self, user: str, password: str):
        # Generate RSA-4096; keep priv in-memory for this session; store encrypted blob server-side for demo
        self.priv, self.pub_b64u, enc_blob, pw_hash = generate_and_encrypt(password)
        await self.send({
            "type":"USER_REGISTER", "ts": now_ms(),
            "payload": {"user_id": user, "pubkey": self.pub_b64u, "privkey_store": enc_blob, "pake_password": pw_hash}
        })

    async def cmd_login(self, user: str, password: str):
        # Request login; server returns your encrypted private key blob so you can decrypt locally
        self.user_id, self.password = user, password
        hello_payload = {"client": "cli-v1"}
        if self.pub_b64u:
            hello_payload["pubkey"] = self.pub_b64u
            hello_payload["enc_pubkey"] = self.pub_b64u
        await self.send({
            "type": "USER_HELLO",
            "from": user,
            "to": "",
            "ts": now_ms(),
            "payload": hello_payload,
        })
        await self.send({"type":"USER_LOGIN","ts":now_ms(),"payload":{"user_id":user,"password":password}})

    async def cmd_list(self):
        await self.send({"type":"LIST_REQUEST", "ts": now_ms()})

    async def cmd_tell(self, to: str, text: str):
        # E2EE DM: encrypt to recipient pubkey, include content_sig over (ciphertext||from||to||ts)
        if not self.user_id or not self.priv:
            print("login first"); return
        if to not in self.pubkeys:
            print("unknown recipient pubkey; try /list"); return
        if not self.pub_b64u and self.user_id in self.pubkeys:
            self.pub_b64u = self.pubkeys[self.user_id]
        if not self.pub_b64u:
            print("missing own pubkey; try /list"); return
        pub = load_public_spki_b64u(self.pubkeys[to])
        ts = now_ms()
        ct = rsa_oaep_encrypt(pub, text.encode("utf-8"))
        # content signature by sender over tuple
        tuple_bytes = b"".join([ct, self.user_id.encode(), to.encode(), str(ts).encode()])
        content_sig = sign_pss_sha256(self.priv, tuple_bytes)
        await self.send({
            "type":"MSG_DIRECT","ts":ts,
            "payload":{
                "to": to,
                "ciphertext": b64u(ct),
                "sender": self.user_id,
                "sender_pub": self.pub_b64u,
                "content_sig": b64u(content_sig)
            }
        })

    async def cmd_all(self, text: str):
        if not self.user_id or not self.priv:
            print("login first"); return
        if not self.pub_b64u and self.user_id in self.pubkeys:
            self.pub_b64u = self.pubkeys[self.user_id]
        if not self.pub_b64u:
            print("missing own pubkey; try /list"); return
        ts = now_ms()
        plaintext = text.encode("utf-8")
        
        # For /all command, send to all known users (excluding self)
        # Don't use public_members as it represents who is IN the channel, not who should RECEIVE
        members = {uid for uid in self.pubkeys if uid != self.user_id}
        
        # Debug: show what members we're trying to send to
        print(f"[debug] attempting to send to members: {sorted(members)}")
        print(f"[debug] available pubkeys: {list(self.pubkeys.keys())}")
        print(f"[debug] self.user_id: {self.user_id}")
        
        sent = 0
        for member in sorted(members):
            if member not in self.pubkeys:
                print(f"skipping {member}: unknown pubkey (try /list)")
                continue
            try:
                pub = load_public_spki_b64u(self.pubkeys[member])
                ct = rsa_oaep_encrypt(pub, plaintext)
            except Exception as e:
                print(f"failed to encrypt for {member}: {e}")
                continue
            sig = self._sign_public_channel(ct, ts)
            payload = {
                "ciphertext": b64u(ct),
                "sender_pub": self.pub_b64u,
                "content_sig": b64u(sig)
            }
            await self.send({
                "type": "MSG_PUBLIC_CHANNEL",
                "from": self.user_id,
                "to": member,
                "ts": ts,
                "payload": payload
            })
            sent += 1
        if not sent:
            print("no recipients for broadcast")

    async def cmd_file(self, to: str, path: str, chunk_size=32*1024):
        if to not in self.pubkeys:
            print("unknown recipient pubkey; try /list"); return
        pub = load_public_spki_b64u(self.pubkeys[to])
        if not os.path.exists(path):
            print(f"file not found: {path}"); return
        size = os.path.getsize(path)
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                buf = fh.read(65536)
                if not buf:
                    break
                h.update(buf)
        digest_hex = h.hexdigest()
        file_id = f"file-{now_ms()}"
        await self.send({"type":"FILE_START","ts":now_ms(),
                         "payload":{"file_id":file_id,"name":os.path.basename(path),"size":size,"sha256":digest_hex,"mode":"dm","to":to}})
        idx = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                ct = rsa_oaep_encrypt(pub, chunk)
                await self.send({"type":"FILE_CHUNK","ts":now_ms(),
                                 "payload":{"file_id":file_id,"index":idx,"ciphertext":b64u(ct),"to":to}})
                idx += 1
        await self.send({"type":"FILE_END","ts":now_ms(),"payload":{"file_id":file_id,"to":to}})

async def repl(url: str):
    c = Client(url)
    await c.connect()
    asyncio.create_task(c.recv_loop())
    print("SOCP client ready. Commands: /register, /login, /list, /tell, /all, /file")
    print("> ", end="", flush=True)

    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line: break
        line = line.strip()
        if not line:
            print("> ", end="", flush=True); continue
        if line.startswith("/"):
            parts = shlex.split(line)
            cmd = parts[0][1:]
            print(f"[debug] parsed command: {cmd}, parts: {parts}")  # Debug output
            try:
                if cmd == "register":
                    _, user, password = parts
                    await c.cmd_register(user, password)
                elif cmd == "login":
                    _, user, password = parts
                    await c.cmd_login(user, password)
                elif cmd == "list":
                    await c.cmd_list()
                elif cmd == "tell":
                    _, to, *rest = parts
                    await c.cmd_tell(to, " ".join(rest))
                elif cmd == "all":
                    _, *rest = parts
                    await c.cmd_all(" ".join(rest))
                elif cmd == "file":
                    if len(parts) < 3:
                        print("usage: /file <user> <path>")
                        continue
                    _, to, path = parts
                    await c.cmd_file(to, path)
                else:
                    print(f"unknown command: {cmd}")
            except ValueError:
                print("bad usage")
        else:
            print("Commands start with /. Try /list or /tell <user> <msg>")
        print("> ", end="", flush=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765")
    args = ap.parse_args()
    try:
        asyncio.run(repl(args.url))
    except KeyboardInterrupt:
        pass
