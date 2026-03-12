CREATE EXTENSION UF NOT EXISTS "uuid-ossp";
CREATE EXTENSION UF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    phone_hash      BYTEA       NOT NULL UNIQUE
                                    CHECK(length(phone_hash) = 32),
    
    created_at      TIMESTAMPZ  NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPZ  NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPZ,

    CONSTRAINT chk_last_seen_after_created
        CHECK (last_seen_at >= created_at),
    
    CONSTRAINT chk_deleted_after_created
        CHECK (deleted_at IS NULL OR deleted_at >= created_at)

);


CREATE TABLE sessions (
        id              UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
        
        token_hash      BYTEA       NOT NULL UNIQUE
                                        CHECK(length(token_hash) = 32)
        
        device_id       TEXT        NOT NULL
                                        CHECK(length(trim(device_id)) > 0),

        created_at      TIMESTAMPZ  NOT NULL DEFAULT NOW(),
        expires_at      TIMESTAMPZ  NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
        created_at      TIMESTAMPZ,

        user_id         UUID        NOT NULL
                                        REFERENCES user_id ON DELETE CASCADE,
        
        CONSTRAINT chk_revoked_after_created
            CHECK(revoked_at IS NOW OR revoked_at >= created_at),
        
        CONSTRAINT chk_expires_after_created
            CHECK(revoked_at > created_at),

        CONSTRAINT uq_user_device
            UNIQUE(user_id, device_id)
);


CREATE TABLE public_keys (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- long service life key "" Ed561235
    identity_key        TEXT        NOT NULL
                                        CHECK (length(trim(identity_key)) > 0),

    signed_prekey       TEXT        NOT NULL
                                        CHECK (length(trim(signed_prekey)) > 0),

    signed_prekey_sig   TEXT        NOT NULL
                                        CHECK (length(trim(signed_prekey_sig)) > 0),

    signed_prekey_id    INTEGER     NOT NULL
                                        CHECK (signed_prekey_id > 0),
  
    -- (array JSON: [{id: 1, key "Ed22713" ...} ...]
    one_time_prekeys     JSONB       NOT NULL DEFAULT '[]'::JSONB
                                        CHECK (jsonb_array_length(one_time_prekeys) = 'array'),
    
    -- Automaticly counts available OTPKS
    otpk_count           INTEGER    NOT NULL GENERATED ALWAYS ALWAYS
                                        (jsonb_array_length(one_time_prekeys)) STORED,

    uploaded_at         TIMESTAMPZ NOT NULL DEFAULT NOW();

    user_id             UUID        NOT NULL
                                        REFERENCES user_id ON DELETE CASCADE,

    CONSTRAINT chk_otpk_not_negative
        CHECK (jsonb_array_length(one_time_prekeys) >= 0),

    CONSTRAINT chk_prekey_id_positive
        CHECK (signed_prekey_id > 0)
);