CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
--CREATE EXTENSION IF NOT EXISTS "pg_cron"; 


/*
..........................
    USERS
..........................
*/

CREATE TABLE users (
    id                  UUID                PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    phone_hash          BYTEA               NOT NULL UNIQUE
                                            CHECK(length(phone_hash) = 32),
    
    created_at          TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,

    CONSTRAINT chk_last_seen_after_created
        CHECK (last_seen_at >= created_at),
    
    CONSTRAINT chk_deleted_after_created
        CHECK (deleted_at IS NULL OR deleted_at >= created_at)

);


/*
..........................
    MESSAGES
..........................
*/


CREATE TABLE messages (

    id         UUID        NOT NULL DEFAULT gen_random_uuid(),

    
    --DOUBLE RATCHET HEADER
    ratchet_key         TEXT            NOT NULL
                                            CHECK (length(trim(ratchet_key)) > 0),
    
    prev_counter        INTEGER         NOT NULL DEFAULT 0
                                            CHECK (prev_counter >= 0),
    
    msg_counter         INTEGER         NOT NULL DEFAULT 0
                                            CHECK (msg_counter >= 0),

    --CiPHERTEXT 
    ciphertext          TEXT            NOT NULL
                                            CHECK (length(trim(ciphertext)) > 0),
    
    iv                  TEXT            NOT NULL
                                            CHECK(length(trim(iv)) > 0),

    message_type        TEXT            NOT NULL DEFAULT 'text' -- 'text' | 'media_ref'
                                            CHECK (message_type IN ('text', 'media_ref')),
    
    created_at          TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    --TTL 7 DAYS
    expires_at          TIMESTAMPTZ      NOT NULL DEFAULT (NOW() + INTERVAL '7 days'),

    --Delivery tracking 

    delivered_at        TIMESTAMPTZ,

    delivery_status     TEXT            NOT NULL DEFAULT 'pending'
                                            CHECK(delivery_status IN ('pending', 'delivered', 'failed')),

    --FK
    sender_id           UUID            NOT NULL
                                            REFERENCES users(id) ON DELETE CASCADE,
    
    recipient_id        UUID            NOT NULL
                                            REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT messages_pkey PRIMARY KEY (id, expires_at),

    CONSTRAINT chk_delivered_after_created
        CHECK (delivered_at IS NULL OR delivered_at >= created_at),

    CONSTRAINT chk_counters_consistency
        CHECK (msg_counter >= prev_counter OR prev_counter = 0),
    
    CONSTRAINT chk_sender_not_reicipient
        CHECK (sender_id <> recipient_id),

    CONSTRAINT chk_delivered_at_consistency
    CHECK (
        (delivery_status = 'delivered' AND delivered_at IS NOT NULL)
        OR
        (delivery_status <> 'delivered' AND delivered_at IS NULL)
    )
) PARTITION BY RANGE (expires_at);

--Default partition(catches everything that does not go into explicit partitions)
CREATE TABLE messages_default PARTITION OF messages DEFAULT;

 --Indexes
CREATE INDEX idx_messages_recipient_pending
    ON messages(recipient_id, created_at)
    WHERE delivery_status = 'pending';

CREATE INDEX idx_messages_expires_at
    ON messages(expires_at);

CREATE INDEX idx_messages_sender
    ON messages(sender_id);




/*
..........................
    SESSIONS
..........................
*/

CREATE TABLE sessions (
        id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
        
        token_hash      BYTEA           NOT NULL UNIQUE
                                            CHECK(length(token_hash) = 32),
        
        device_id       TEXT            NOT NULL
                                            CHECK(length(trim(device_id)) > 0),

        created_at      TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
        expires_at      TIMESTAMPTZ      NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
        revoked_at      TIMESTAMPTZ,

        user_id         UUID            NOT NULL
                                            REFERENCES users(id) ON DELETE CASCADE,
        
        CONSTRAINT chk_revoked_after_created
            CHECK(revoked_at IS NULL OR revoked_at >= created_at),
        
        CONSTRAINT chk_expires_after_created
            CHECK(expires_at > created_at),

        CONSTRAINT uq_user_device
            UNIQUE(user_id, device_id)
);


/*
..........................
    PUBLIC KEYS
..........................
*/


CREATE TABLE public_keys (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- long service life key "" Ed561235
    identity_key        TEXT            NOT NULL
                                            CHECK (length(trim(identity_key)) > 0),

    signed_prekey       TEXT            NOT NULL
                                            CHECK (length(trim(signed_prekey)) > 0),

    signed_prekey_sig   TEXT            NOT NULL
                                            CHECK (length(trim(signed_prekey_sig)) > 0),

    signed_prekey_id    INTEGER         NOT NULL
                                            CHECK (signed_prekey_id > 0),
                                        
    -- (array JSON: [{id: 1, key "Ed22713" ...} ...]
    one_time_prekeys     JSONB          NOT NULL DEFAULT '[]'::JSONB
                                            CHECK (jsonb_typeof(one_time_prekeys) = 'array'),
    
    -- Automaticly counts available OTPKS
    otpk_count           INTEGER        NOT NULL GENERATED ALWAYS AS
                                            (jsonb_array_length(one_time_prekeys)) STORED,

    uploaded_at         TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    user_id             UUID            NOT NULL UNIQUE
                                            REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT chk_otpk_not_negative
        CHECK (jsonb_array_length(one_time_prekeys) >= 0),

    CONSTRAINT chk_prekey_id_positive
        CHECK (signed_prekey_id > 0)
);





/*
..........................
    MEDIA REFERENCES
..........................
*/

CREATE TABLE media_references (

    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    message_id          UUID, 
    
    message_expires_at  TIMESTAMPTZ,

    storage_key         TEXT            NOT NULL UNIQUE,

    mime_type           TEXT            NOT NULL,

    size_bytes          BIGINT           NOT NULL,
 
    created_at          TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    expires_at          TIMESTAMPTZ      NOT NULL DEFAULT (NOW() + INTERVAL '48 hours')
                                            CHECK(expires_at > created_at),
                                            
    deleted_at          TIMESTAMPTZ,

    uploader_id         UUID            NOT NULL
                                            REFERENCES users(id),

    recipient_id        UUID            NOT NULL
                                            REFERENCES users(id),
    
    FOREIGN KEY (message_id, message_expires_at)
        REFERENCES messages(id, expires_at) ON DELETE SET NULL
);

/*
..........................
    OTP REQUESTS
..........................
*/

CREATE TABLE otp_requests (

    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    phone_hash          BYTEA               NOT NULL
                                                CHECK(length(phone_hash) = 32),

    otp_hash            BYTEA               NOT NULL
                                                CHECK(length(otp_hash) = 32),

    created_at          TIMESTAMPTZ          NOT NULL DEFAULT NOW(),

    expires_at          TIMESTAMPTZ          NOT NULL DEFAULT(NOW() + INTERVAL '10 minutes')
                                                CHECK(expires_at > created_at),

    verified_at         TIMESTAMPTZ,

    attempts            SMALLINT            NOT NULL DEFAULT 0
                                                CHECK(attempts <= 5),
    
    max_attempts        SMALLINT                NOT NULL DEFAULT 5
                                                    CHECK(max_attempts BETWEEN 1 AND 10),
    
    CONSTRAINT chk_verified_after_created
        CHECK(verified_at IS NULL OR verified_at >= created_at),

    CONSTRAINT chk_verified_before_expiry
        CHECK(verified_at IS NULL OR verified_at <= expires_at),    

    CONSTRAINT chk_attempts_le_max
        CHECK (attempts <= max_attempts)
);

--INDEXES
CREATE INDEX idx_otp_phone_hash ON otp_requests (phone_hash);
CREATE INDEX idx_otp_expires_at ON otp_requests (expires_at);


/*
..........................
    delivery_acks
..........................
*/


CREATE TABLE delivery_acks (
    id                  UUID                PRIMARY KEY DEFAULT uuid_generate_v4(),

    message_id          UUID                NOT NULL,


    acked_at            TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    expires_at          TIMESTAMPTZ         NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
                                               CHECK (expires_at > acked_at),

    recipient_id        UUID                NOT NULL
                                                REFERENCES users(id) ON DELETE CASCADE,


    CONSTRAINT chk_acked_before_expiry
        CHECK (acked_at < expires_at),

    CONSTRAINT uq_message_recipient
        UNIQUE (message_id, recipient_id)


);

CREATE OR REPLACE FUNCTION fn_delete_delivered_message()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM messages WHERE id = NEW.message_id;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_delete_on_ack
    AFTER INSERT ON delivery_acks
    FOR EACH ROW
    EXECUTE FUNCTION fn_delete_delivered_message();

-- INDEXES
CREATE INDEX idx_acks_message_id  ON delivery_acks (message_id);
CREATE INDEX idx_acks_expires_at  ON delivery_acks (expires_at);
CREATE INDEX idx_acks_recipient   ON delivery_acks (recipient_id);


