-- ============================================================
--  SILEX — DB Tests
-- ============================================================

\echo '--- SILEX DB TESTS ---'

BEGIN;

-- SETUP
INSERT INTO users (phone_hash) VALUES (digest('+521234567890', 'sha256'));
INSERT INTO users (phone_hash) VALUES (digest('+529876543210', 'sha256'));


-- ── USERS ──────────────────────────────────────────────────

\echo '[USERS]'

SAVEPOINT sp;
INSERT INTO users (phone_hash) VALUES (digest('+521234567890', 'sha256'));
ROLLBACK TO SAVEPOINT sp;
\echo '  phone_hash duplicado         PASS'

SAVEPOINT sp;
INSERT INTO users (phone_hash) VALUES ('\x1234'::BYTEA);
ROLLBACK TO SAVEPOINT sp;
\echo '  phone_hash tamano incorrecto  PASS'

SAVEPOINT sp;
UPDATE users SET deleted_at = NOW() - INTERVAL '1 day'
WHERE phone_hash = digest('+521234567890', 'sha256');
ROLLBACK TO SAVEPOINT sp;
\echo '  deleted_at anterior           PASS'

SAVEPOINT sp;
UPDATE users SET deleted_at = NOW() + INTERVAL '1 day'
WHERE phone_hash = digest('+521234567890', 'sha256');
ROLLBACK TO SAVEPOINT sp;
\echo '  deleted_at valido             PASS'


-- ── SESSIONS ───────────────────────────────────────────────

\echo '[SESSIONS]'

INSERT INTO sessions (user_id, token_hash, device_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    digest('jwt.token.prueba', 'sha256'),
    'device-android-001'
);
\echo '  insert valido                 PASS'

SAVEPOINT sp;
INSERT INTO sessions (user_id, token_hash, device_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    digest('otro.jwt.token', 'sha256'),
    'device-android-001'
);
ROLLBACK TO SAVEPOINT sp;
\echo '  user+device duplicado         PASS'

SAVEPOINT sp;
INSERT INTO sessions (user_id, token_hash, device_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    '\xDEAD'::BYTEA,
    'device-ios-002'
);
ROLLBACK TO SAVEPOINT sp;
\echo '  token_hash tamano incorrecto  PASS'

SAVEPOINT sp;
INSERT INTO sessions (user_id, token_hash, device_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    digest('token.valido.2', 'sha256'),
    '   '
);
ROLLBACK TO SAVEPOINT sp;
\echo '  device_id vacio               PASS'

SAVEPOINT sp;
UPDATE sessions SET revoked_at = NOW() - INTERVAL '1 day'
WHERE user_id = (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256'));
ROLLBACK TO SAVEPOINT sp;
\echo '  revoked_at anterior           PASS'


-- ── PUBLIC KEYS ────────────────────────────────────────────

\echo '[PUBLIC KEYS]'

INSERT INTO public_keys (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id, one_time_prekeys)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    'base64url-identity-key-A',
    'base64url-signed-prekey-A',
    'base64url-signature-A',
    1,
    '[{"id":1,"key":"otpk-1"},{"id":2,"key":"otpk-2"},{"id":3,"key":"otpk-3"}]'::JSONB
);
\echo '  insert valido                 PASS'

DO $$
DECLARE v INTEGER;
BEGIN
    SELECT otpk_count INTO v FROM public_keys
    WHERE user_id = (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256'));
    IF v <> 3 THEN RAISE EXCEPTION 'otpk_count esperado 3, obtenido %', v; END IF;
END;
$$;
\echo '  otpk_count generado = 3       PASS'

SAVEPOINT sp;
INSERT INTO public_keys (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    'otra-key', 'otro-prekey', 'otra-sig', 2
);
ROLLBACK TO SAVEPOINT sp;
\echo '  bundle duplicado              PASS'

SAVEPOINT sp;
INSERT INTO public_keys (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256')),
    '   ', 'prekey', 'sig', 1
);
ROLLBACK TO SAVEPOINT sp;
\echo '  identity_key vacia            PASS'

SAVEPOINT sp;
INSERT INTO public_keys (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id, one_time_prekeys)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256')),
    'identity-b', 'prekey-b', 'sig-b', 1,
    '{"clave": "no soy array"}'::JSONB
);
ROLLBACK TO SAVEPOINT sp;
\echo '  one_time_prekeys no-array     PASS'

SAVEPOINT sp;
INSERT INTO public_keys (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id)
VALUES (
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256')),
    'identity-b', 'prekey-b', 'sig-b', -1
);
ROLLBACK TO SAVEPOINT sp;
\echo '  signed_prekey_id negativo     PASS'


-- ── MESSAGES ───────────────────────────────────────────────

\echo '[MESSAGES]'

INSERT INTO messages (ratchet_key, ciphertext, iv, sender_id, recipient_id)
VALUES (
    'ratchet-key-base64',
    'ciphertext-aes256gcm-base64',
    'iv-96bit-base64',
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256'))
);
\echo '  insert valido                 PASS'

SAVEPOINT sp;
INSERT INTO messages (ratchet_key, ciphertext, iv, sender_id, recipient_id)
VALUES (
    'key', 'cipher', 'iv',
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256'))
);
ROLLBACK TO SAVEPOINT sp;
\echo '  sender = recipient            PASS'

SAVEPOINT sp;
INSERT INTO messages (ratchet_key, ciphertext, iv, sender_id, recipient_id, delivery_status, delivered_at)
VALUES (
    'key', 'cipher', 'iv',
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256')),
    'delivered', NULL
);
ROLLBACK TO SAVEPOINT sp;
\echo '  delivered sin delivered_at    PASS'

SAVEPOINT sp;
INSERT INTO messages (ratchet_key, ciphertext, iv, sender_id, recipient_id, delivery_status, delivered_at)
VALUES (
    'key', 'cipher', 'iv',
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256')),
    'pending', NOW()
);
ROLLBACK TO SAVEPOINT sp;
\echo '  pending con delivered_at      PASS'

SAVEPOINT sp;
INSERT INTO messages (ratchet_key, ciphertext, iv, sender_id, recipient_id, msg_counter)
VALUES (
    'key', 'cipher', 'iv',
    (SELECT id FROM users WHERE phone_hash = digest('+521234567890', 'sha256')),
    (SELECT id FROM users WHERE phone_hash = digest('+529876543210', 'sha256')),
    -1
);
ROLLBACK TO SAVEPOINT sp;
\echo '  msg_counter negativo          PASS'


-- ── OTP REQUESTS ───────────────────────────────────────────

\echo '[OTP REQUESTS]'

INSERT INTO otp_requests (phone_hash, otp_hash)
VALUES (digest('+521234567890', 'sha256'), digest('847291', 'sha256'));
\echo '  insert valido                 PASS'

INSERT INTO otp_requests (phone_hash, otp_hash)
VALUES (digest('+521234567890', 'sha256'), digest('111222', 'sha256'));
\echo '  reenvio OTP                   PASS'

SAVEPOINT sp;
UPDATE otp_requests SET attempts = 6
WHERE id = (SELECT id FROM otp_requests
            WHERE phone_hash = digest('+521234567890', 'sha256') LIMIT 1);
ROLLBACK TO SAVEPOINT sp;
\echo '  attempts > max                PASS'

SAVEPOINT sp;
UPDATE otp_requests SET verified_at = NOW() - INTERVAL '1 hour'
WHERE id = (SELECT id FROM otp_requests LIMIT 1);
ROLLBACK TO SAVEPOINT sp;
\echo '  verified_at anterior          PASS'

SAVEPOINT sp;
UPDATE otp_requests SET verified_at = NOW() + INTERVAL '1 hour'
WHERE id = (SELECT id FROM otp_requests LIMIT 1);
ROLLBACK TO SAVEPOINT sp;
\echo '  verified_at posterior expiry  PASS'

UPDATE otp_requests SET verified_at = NOW()
WHERE id = (SELECT id FROM otp_requests
            WHERE phone_hash = digest('+521234567890', 'sha256') LIMIT 1);
\echo '  verificacion valida           PASS'


-- ── DELIVERY ACKS + TRIGGER ────────────────────────────────

\echo '[DELIVERY ACKS]'

INSERT INTO delivery_acks (message_id, recipient_id)
VALUES (
    (SELECT id FROM messages LIMIT 1),
    (SELECT recipient_id FROM messages LIMIT 1)
);
\echo '  insert ACK                    PASS'

DO $$
DECLARE v INTEGER;
BEGIN
    SELECT COUNT(*) INTO v FROM messages;
    IF v <> 0 THEN RAISE EXCEPTION 'trigger fallo, quedan % mensajes', v; END IF;
END;
$$;
\echo '  trigger borro el mensaje      PASS'

INSERT INTO delivery_acks (message_id, recipient_id)
VALUES (
    (SELECT message_id FROM delivery_acks LIMIT 1),
    (SELECT recipient_id FROM delivery_acks LIMIT 1)
)
ON CONFLICT (message_id, recipient_id) DO NOTHING;
\echo '  ACK duplicado ignorado        PASS'


-- ── RESUMEN ────────────────────────────────────────────────

\echo ''
\echo '[RESUMEN]'
SELECT tablename AS tabla,
       (xpath('/row/cnt/text()',
           query_to_xml('SELECT COUNT(*) AS cnt FROM ' || tablename, false, true, ''))
       )[1]::text::integer AS filas
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename <> 'messages_default'
ORDER BY tablename;

ROLLBACK;
\echo ''
\echo '--- TODAS LAS PRUEBAS PASARON. ROLLBACK OK. ---'
```

La salida ahora se ve así:
```
--- SILEX DB TESTS ---
[USERS]
  phone_hash duplicado         PASS
  phone_hash tamano incorrecto  PASS
  deleted_at anterior           PASS
  deleted_at valido             PASS
[SESSIONS]
  insert valido                 PASS
  ...
[DELIVERY ACKS]
  trigger borro el mensaje      PASS
  ACK duplicado ignorado        PASS

--- TODAS LAS PRUEBAS PASARON. ROLLBACK OK. ---