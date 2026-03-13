import {
  ConflictException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { DatabaseService } from '../database/database.service';

// ---------------------------------------------------------------------------
// Types matching the real DB schema
// ---------------------------------------------------------------------------

interface OtpRequestRow {
  id: string;
  phone_hash: Buffer;
  otp_hash: Buffer;       // BYTEA 32 bytes
  expires_at: Date;
  verified_at: Date | null;
  attempts: number;
  max_attempts: number;
}

interface UserRow {
  id: string;
  phone_hash: Buffer;
}

interface SessionRow {
  id: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OTP_LENGTH = 6;
const OTP_RATE_LIMIT_SECONDS = 60;

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly db: DatabaseService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  // -------------------------------------------------------------------------
  // POST /auth/request-otp
  // -------------------------------------------------------------------------

  async requestOtp(phone: string): Promise<{ message: string; otp?: string }> {
    const phoneHash = this.hashPhone(phone);

    // Upsert user — phone_hash is the only identifier stored
    const user = await this.upsertUser(phoneHash);

    // Rate-limit: reject if a non-expired, unverified OTP was issued recently
    await this.assertNoRecentOtp(phoneHash);

    // Generate OTP and hash it to BYTEA (32 bytes = SHA-256)
    const plainOtp = this.generateOtp();
    const otpHashBuffer = this.hashOtpToBuffer(plainOtp);

    // Insert into otp_requests — schema uses phone_hash directly, no user_id
    await this.db.query(
      `INSERT INTO otp_requests (phone_hash, otp_hash)
       VALUES ($1, $2)`,
      [phoneHash, otpHashBuffer],
    );

    this.logger.log(`OTP issued for user ${user.id}`);

    // In production: hand plainOtp to SMS provider, never log or return it.
    const isDev = this.config.get<string>('NODE_ENV') !== 'production';
    return {
      message: 'OTP sent successfully.',
      ...(isDev && { otp: plainOtp }),
    };
  }

  // -------------------------------------------------------------------------
  // POST /auth/verify-otp
  // -------------------------------------------------------------------------

  async verifyOtp(
    phone: string,
    code: string,
    deviceId: string = 'default',
  ): Promise<{ accessToken: string; userId: string }> {
    const phoneHash = this.hashPhone(phone);

    // Resolve user — must exist (created on request-otp)
    const user = await this.findUserByPhoneHash(phoneHash);
    if (!user) {
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Find the most recent active OTP for this phone_hash
    const otpRequest = await this.findActiveOtpRequest(phoneHash);
    if (!otpRequest) {
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Increment attempts before comparing — closes the race condition window
    const updatedAttempts = await this.incrementOtpAttempt(otpRequest.id);
    if (updatedAttempts > otpRequest.max_attempts) {
      throw new UnauthorizedException('Too many attempts. Request a new OTP.');
    }

    // Constant-time comparison of hashed OTPs (both are 32-byte Buffers)
    const candidateHash = this.hashOtpToBuffer(code);
    const valid = crypto.timingSafeEqual(candidateHash, otpRequest.otp_hash);

    if (!valid) {
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Mark OTP verified + create session atomically
    const { session, tokenPlain } = await this.db.withTransaction(async (client) => {
      // Mark verified
      await client.query(
        `UPDATE otp_requests SET verified_at = NOW() WHERE id = $1`,
        [otpRequest.id],
      );

      // sessions requires: token_hash (BYTEA 32), device_id, user_id
      const tokenPlain = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto
        .createHash('sha256')
        .update(tokenPlain)
        .digest();

      const { rows } = await client.query<SessionRow>(
        `INSERT INTO sessions (user_id, token_hash, device_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, device_id)
         DO UPDATE SET
           token_hash = EXCLUDED.token_hash,
           created_at = NOW(),
           expires_at = NOW() + INTERVAL '30 days',
           revoked_at = NULL
         RETURNING id`,
        [user.id, tokenHash, deviceId],
      );

      return { session: rows[0], tokenPlain };
    });

    // JWT payload: sub = user id, sid = session id
    const accessToken = this.jwt.sign({
      sub: user.id,
      sid: session.id,
    });

    this.logger.log(`Session created for user ${user.id}, session ${session.id}`);

    return { accessToken, userId: user.id };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** SHA-256 of E.164 phone number → 32-byte Buffer (stored as BYTEA) */
  private hashPhone(phone: string): Buffer {
    return crypto.createHash('sha256').update(phone, 'utf8').digest();
  }

  /** SHA-256(code + OTP_SECRET) → 32-byte Buffer (stored as BYTEA) */
  private hashOtpToBuffer(code: string): Buffer {
    return crypto
      .createHash('sha256')
      .update(code + this.config.getOrThrow<string>('OTP_SECRET'))
      .digest();
  }

  /** Cryptographically random 6-digit string */
  private generateOtp(): string {
    const bytes = crypto.randomBytes(4);
    const num = bytes.readUInt32BE(0) % 1_000_000;
    return num.toString().padStart(OTP_LENGTH, '0');
  }

  private async upsertUser(phoneHash: Buffer): Promise<UserRow> {
    const { rows } = await this.db.query<UserRow>(
      `INSERT INTO users (phone_hash)
       VALUES ($1)
       ON CONFLICT (phone_hash) DO UPDATE SET last_seen_at = NOW()
       RETURNING id, phone_hash`,
      [phoneHash],
    );
    return rows[0];
  }

  private async findUserByPhoneHash(phoneHash: Buffer): Promise<UserRow | null> {
    const { rows } = await this.db.query<UserRow>(
      `SELECT id, phone_hash FROM users WHERE phone_hash = $1`,
      [phoneHash],
    );
    return rows[0] ?? null;
  }

  /** Rate-limit: reject if there's a recent unverified non-expired OTP */
  private async assertNoRecentOtp(phoneHash: Buffer): Promise<void> {
    const { rows } = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) AS count
       FROM otp_requests
       WHERE phone_hash = $1
         AND verified_at IS NULL
         AND expires_at > NOW()
         AND created_at > NOW() - INTERVAL '${OTP_RATE_LIMIT_SECONDS} seconds'`,
      [phoneHash],
    );

    if (parseInt(rows[0].count, 10) > 0) {
      throw new ConflictException(
        `Please wait ${OTP_RATE_LIMIT_SECONDS} seconds before requesting a new OTP.`,
      );
    }
  }

  private async findActiveOtpRequest(
    phoneHash: Buffer,
  ): Promise<OtpRequestRow | null> {
    const { rows } = await this.db.query<OtpRequestRow>(
      `SELECT id, phone_hash, otp_hash, expires_at, verified_at, attempts, max_attempts
       FROM otp_requests
       WHERE phone_hash = $1
         AND verified_at IS NULL
         AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [phoneHash],
    );
    return rows[0] ?? null;
  }

  /** Increments attempts and returns the new value */
  private async incrementOtpAttempt(otpRequestId: string): Promise<number> {
    const { rows } = await this.db.query<{ attempts: number }>(
      `UPDATE otp_requests
       SET attempts = attempts + 1
       WHERE id = $1
       RETURNING attempts`,
      [otpRequestId],
    );
    return rows[0].attempts;
  }
}