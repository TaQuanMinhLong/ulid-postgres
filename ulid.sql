-- Active: 1704953614607@@127.0.0.1@5432@user_service@public
-- DROP FUNCTION is_valid_ulid;
CREATE
OR REPLACE FUNCTION is_valid_ulid (TEXT) RETURNS BOOLEAN AS $$
  SELECT char_length($1) = 26 AND trim('0123456789ABCDEFGHJKMNPQRSTVWXYZ' from upper($1)) = '';
$$ LANGUAGE SQL IMMUTABLE;

CREATE TYPE ulid AS (inner_ulid CHAR(26));

-- DROP FUNCTION ulid_from_text;
CREATE
OR REPLACE FUNCTION ulid_from_text (TEXT) RETURNS ulid AS $$
BEGIN
    IF is_valid_ulid($1) IS FALSE THEN
        RAISE EXCEPTION 'Invalid ULID';
    END IF;
    RETURN ROW($1)::ulid;
END
$$ LANGUAGE plpgsql;

-- DROP FUNCTION ulid_to_text;
CREATE
OR REPLACE FUNCTION ulid_to_text (ulid) RETURNS TEXT AS $$
BEGIN
    RETURN ($1).inner_ulid;
END
$$ LANGUAGE plpgsql;

-- DROP CAST (ulid AS TEXT);
CREATE CAST (ulid AS TEXT)
WITH
    FUNCTION ulid_to_text (ulid) AS IMPLICIT;

-- DROP CAST (text AS ulid);
CREATE CAST (TEXT AS ulid)
WITH
    FUNCTION ulid_from_text (TEXT) AS IMPLICIT;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- DROP FUNCTION decode_ulid;
CREATE
OR REPLACE FUNCTION gen_ulid () RETURNS TEXT AS $$
DECLARE
  -- Crockford's Base32
  encoding   BYTEA = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  timestamp  BYTEA = E'\\000\\000\\000\\000\\000\\000';
  output     TEXT = '';

  unix_time  BIGINT;
  ulid       BYTEA;
BEGIN
  -- 6 timestamp bytes
  unix_time = (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP()) * 1000)::BIGINT;
  timestamp = SET_BYTE(timestamp, 0, (unix_time >> 40)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 1, (unix_time >> 32)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 2, (unix_time >> 24)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 3, (unix_time >> 16)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 4, (unix_time >> 8)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 5, unix_time::BIT(8)::INTEGER);

  -- 10 entropy bytes
  ulid = timestamp || gen_random_bytes(10);

  -- Encode the timestamp
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 0) & 224) >> 5));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 0) & 31)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 1) & 248) >> 3));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 1) & 7) << 2) | ((GET_BYTE(ulid, 2) & 192) >> 6)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 2) & 62) >> 1));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 2) & 1) << 4) | ((GET_BYTE(ulid, 3) & 240) >> 4)));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 3) & 15) << 1) | ((GET_BYTE(ulid, 4) & 128) >> 7)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 4) & 124) >> 2));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 4) & 3) << 3) | ((GET_BYTE(ulid, 5) & 224) >> 5)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 5) & 31)));

  -- Encode the entropy
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 6) & 248) >> 3));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 6) & 7) << 2) | ((GET_BYTE(ulid, 7) & 192) >> 6)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 7) & 62) >> 1));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 7) & 1) << 4) | ((GET_BYTE(ulid, 8) & 240) >> 4)));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 8) & 15) << 1) | ((GET_BYTE(ulid, 9) & 128) >> 7)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 9) & 124) >> 2));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 9) & 3) << 3) | ((GET_BYTE(ulid, 10) & 224) >> 5)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 10) & 31)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 11) & 248) >> 3));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 11) & 7) << 2) | ((GET_BYTE(ulid, 12) & 192) >> 6)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 12) & 62) >> 1));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 12) & 1) << 4) | ((GET_BYTE(ulid, 13) & 240) >> 4)));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 13) & 15) << 1) | ((GET_BYTE(ulid, 14) & 128) >> 7)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 14) & 124) >> 2));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 14) & 3) << 3) | ((GET_BYTE(ulid, 15) & 224) >> 5)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 15) & 31)));

  RETURN output;
END
$$ LANGUAGE plpgsql VOLATILE;

-- DROP FUNCTION decode_ulid;
CREATE
OR REPLACE FUNCTION decode_ulid (ulid_str CHAR(26)) RETURNS BIGINT AS $$
DECLARE
    i INT;
    encode_idx INT;
    time_str CHAR(10);
    curr_char CHAR(1);
    timestamp BIGINT;
    TIME_MAX CONSTANT BIGINT := power(2, 48) - 1;
    TIME_LEN CONSTANT INT := 10;
    ENCODING CONSTANT CHAR(32) := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    ENCODING_LEN CONSTANT INT := 32;
BEGIN
    timestamp := 0;
    time_str := substring(ulid_str FROM 1 FOR TIME_LEN);
    FOR i IN 1..TIME_LEN LOOP
        curr_char := substring(reverse(time_str) FROM i FOR 1);
        encode_idx := POSITION(curr_char IN ENCODING) - 1;
        IF encode_idx < 0 THEN
            RAISE EXCEPTION 'Invalid character found: %', curr_char;
        END IF;
        timestamp := timestamp + encode_idx * POWER(ENCODING_LEN, i - 1);
    END LOOP;

    IF timestamp > TIME_MAX THEN
        RAISE EXCEPTION 'Malformed ulid, timestamp too large';
    END IF;

    -- Timestamp as epoch in seconds
    RETURN timestamp / 1000;

    EXCEPTION
        WHEN OTHERS THEN
            RAISE EXCEPTION 'Error decoding ULID: %', SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- DROP FUNCTION ulid_to_epoch;
CREATE
OR REPLACE FUNCTION ulid_to_epoch (ulid ulid) RETURNS BIGINT AS $$
BEGIN
    RETURN decode_ulid(ulid::text);
END
$$ LANGUAGE plpgsql;

-- DROP CAST (ulid AS BIGINT);
CREATE CAST (ulid AS BIGINT)
WITH
    FUNCTION ulid_to_epoch (ulid) AS IMPLICIT;

-- DROP FUNCTION ulid_to_timestamp;
CREATE
OR REPLACE FUNCTION ulid_to_timestamp (ulid ulid) RETURNS TIMESTAMP AS $$
BEGIN
    RETURN to_timestamp(ulid::BIGINT);
END;
$$ LANGUAGE plpgsql;

-- DROP CAST (ulid AS TIMESTAMP)
CREATE CAST (ulid AS TIMESTAMP)
WITH
    FUNCTION ulid_to_timestamp (ulid) AS IMPLICIT;
