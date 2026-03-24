"""
OPC UA Server — SignEncrypt-only, all available policies, proper PKI truststore
Requires: pip install asyncua cryptography

Security Policies (MessageSecurityMode.SignAndEncrypt only):
  - Basic256Sha256_SignAndEncrypt
  - Aes128_Sha256_RsaOaep_SignAndEncrypt
  - Aes256_Sha256_RsaPss_SignAndEncrypt

PKI layout expected under  certs/
  certs/
    server_cert.der
    server_key.pem
    certificates/
      trusted/
        certs/          ← place every trusted client .der here
      issuers/
        certs/          ← intermediate / root CA certs (if any)

Run generate_certs.py first to create server_cert.der / server_key.pem.
"""

import asyncio
import logging
import math
from pathlib import Path

from asyncua import Server, ua
from asyncua.crypto.permission_rules import SimpleRoleRuleset
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.server.user_managers import CertificateUserManager
from asyncua.common.connection import TransportLimits

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
log = logging.getLogger("opcua.server")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
CERT_BASE     = BASE_DIR / "certs"

SERVER_CERT   = CERT_BASE / "server_cert.der"
SERVER_KEY    = CERT_BASE / "server_key.pem"

# Drop any client .der certificate here to admit that client
TRUSTED_CERTS = CERT_BASE / "trusted"
# Intermediate / root CA certs for chain validation (empty = self-signed setup)
ISSUER_CERTS  = CERT_BASE / "issuers"

# Known client certs — adjust paths / add entries as needed
CLIENT_CERT_PYTHON = TRUSTED_CERTS / "python_client.der"
CLIENT_CERT_UAEX   = TRUSTED_CERTS / "ua_expert.der"

# ── Server identity ───────────────────────────────────────────────────────────
# MUST match the URI in the server certificate's SubjectAlternativeName!
SERVER_APP_URI  = f"urn:freeopcua:interface_server"
SERVER_ENDPOINT = "opc.tcp://0.0.0.0:4840/freeopcua/server/"

# ── Transport limits ──────────────────────────────────────────────────────────
BUFFER_SZ  = 65_536      # 64 KB per chunk
MAX_MSG_SZ = 16_777_216  # 16 MB total message


# ── Address space ─────────────────────────────────────────────────────────────
async def populate_address_space(server: Server):
    """Minimal demo namespace: folder, variables, and an Echo method."""
    idx    = await server.register_namespace(SERVER_APP_URI)
    folder = await server.nodes.objects.add_folder(idx, "DemoData")

    await folder.add_variable(idx, "ServerName", "SignEncrypt Demo Server")
    await folder.add_variable(idx, "Pi",         3.14159265)

    counter = await folder.add_variable(idx, "TickCounter", 0)
    await counter.set_writable()

    async def echo_method(parent, txt: ua.Variant):
        log.info("Echo('%s') called", txt.Value)
        return [ua.Variant(f"ECHO: {txt.Value}", ua.VariantType.String)]

    await folder.add_method(
        idx, "Echo", echo_method,
        [ua.VariantType.String],
        [ua.VariantType.String],
    )

    log.info("Address space ready — namespace index %d", idx)
    return counter


# ── Main ─────────────────────────────────────────────────────────────────────
async def main() -> None:

    # ── Sanity checks ────────────────────────────────────────────────────────
    for path, label in [
        (SERVER_CERT, "server certificate"),
        (SERVER_KEY,  "server private key"),
    ]:
        if not path.exists():
            log.error("Missing %s: %s — run generate_certs.py first.", label, path)
            return

    # Ensure PKI directories exist (harmless if already present)
    TRUSTED_CERTS.mkdir(parents=True, exist_ok=True)
    ISSUER_CERTS.mkdir(parents=True, exist_ok=True)

    # ── CertificateUserManager ────────────────────────────────────────────────
    # Maps a client certificate to a named identity (and implicitly to a role
    # via SimpleRoleRuleset).  Only certs registered here are allowed to open
    # a session — everything else is rejected at the application layer even
    # if the TLS handshake would otherwise succeed.
    cert_user_manager = CertificateUserManager()

    for cert_path, name, role in [
        (CLIENT_CERT_PYTHON, "Python-Client",    "user"),
        (CLIENT_CERT_UAEX,   "UA-Expert-Client", "user"),
    ]:
        if cert_path.exists():
            if role == "admin":
                await cert_user_manager.add_admin(cert_path, name=name)
            else:
                await cert_user_manager.add_user(cert_path, name=name)
            log.info("Registered  %-34s → %s (%s)", cert_path.name, name, role)
        else:
            log.warning("Client cert not found, skipping: %s", cert_path)

    # ── Server construction ───────────────────────────────────────────────────
    server = Server(user_manager=cert_user_manager)
    await server.init()

    await server.set_application_uri(SERVER_APP_URI)
    server.set_endpoint(SERVER_ENDPOINT)

    # ── Transport limits ──────────────────────────────────────────────────────
    server.limits = TransportLimits(
        max_recv_buffer=BUFFER_SZ,
        max_send_buffer=BUFFER_SZ,
        max_chunk_count=math.ceil(MAX_MSG_SZ / BUFFER_SZ),
        max_message_size=MAX_MSG_SZ,
    )

    # ── Security policies — SignAndEncrypt ONLY ───────────────────────────────
    #
    # All three asyncua SignAndEncrypt variants are registered.
    # Clients negotiate the best mutual policy during the handshake.
    #
    #   Basic256Sha256_SignAndEncrypt   — RSA-OAEP(SHA-1),  AES-256-CBC, SHA-256 HMAC
    #   Aes128_Sha256_RsaOaep_…        — RSA-OAEP(SHA-1),  AES-128-CBC, SHA-256 HMAC
    #   Aes256_Sha256_RsaPss_…         — RSA-PSS/SHA-256,  AES-256-CBC, RSA-OAEP-SHA-256
    #
    # MessageSecurityMode.None_ and .Sign are intentionally absent.
    server.set_security_policy(
        [
            ua.SecurityPolicyType.Basic128Rsa15_SignAndEncrypt,
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
            ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
        ],
        permission_ruleset=SimpleRoleRuleset(),  # maps UserRole → node access rights
    )

    # ── Server PKI material ───────────────────────────────────────────────────
    await server.load_certificate(str(SERVER_CERT))
    await server.load_private_key(str(SERVER_KEY))

    # ── TrustStore ────────────────────────────────────────────────────────────
    # TrustStore(trusted_paths, issuer_paths)
    #   trusted_paths — self-signed client certs OR end-entity certs signed by
    #                   a trusted CA that is itself placed in issuer_paths.
    #   issuer_paths  — intermediate / root CA certs for chain validation.
    #                   Leave the list non-empty but the directory empty for a
    #                   fully self-signed setup; asyncua handles it gracefully.
    trust_store = TrustStore(
        [TRUSTED_CERTS],  # leaf / CA certs explicitly trusted
        [ISSUER_CERTS],   # issuer chain (empty dir = self-signed only)
    )
    await trust_store.load()

    # ── CertificateValidator ──────────────────────────────────────────────────
    # TRUSTED_VALIDATION  — cert must appear in (or chain to) the trust store
    # PEER_CLIENT         — apply validation to the connecting client's cert
    # Together they enforce that every client presents a known, valid cert
    # before a SecureChannel is established.
    validator = CertificateValidator(
        options=(
            CertificateValidatorOptions.TRUSTED_VALIDATION
            | CertificateValidatorOptions.PEER_CLIENT
        ),
        trust_store=trust_store,
    )
    server.set_certificate_validator(validator)

    log.info("TrustStore loaded  →  %s", TRUSTED_CERTS)
    log.info("Security policies active:")
    log.info("  • Basic256Sha256          / SignAndEncrypt")
    log.info("  • Aes128_Sha256_RsaOaep   / SignAndEncrypt")
    log.info("  • Aes256_Sha256_RsaPss    / SignAndEncrypt")

    # ── Populate address space ────────────────────────────────────────────────
    counter = await populate_address_space(server)

    # ── Run ───────────────────────────────────────────────────────────────────
    async with server:
        log.info("OPC UA server listening on  %s", SERVER_ENDPOINT)
        log.info("Press Ctrl-C to stop.")

        tick = 0
        while True:
            await asyncio.sleep(1)
            tick += 1
            await counter.write_value(tick)
            if tick % 10 == 0:
                log.info("Tick %d", tick)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutdown requested — bye.")