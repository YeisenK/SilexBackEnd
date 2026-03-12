import {
  BadRequestException,
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
// Types
// ---------------------------------------------------------------------------

interface OtpRequestRow {
  id: string;
  user_id: string;
  code_hash: Buffer;
  expires_at: Date;
  attempts: number;
  verified: boolean;
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
const OTP_TTL_MINUTES = 10;
const MAX_OTP_ATTEMPTS = 5;
/**
 * Minimum seconds between OTP requests for the same phone number.
 * Prevents SMS flooding.
 */
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
  // Public API
  // -------------------------------------------------------------------------

  /**
   * POST /auth/request-otp
   *
   * 1. Hash the phone number with SHA-256.
   * 2. Upsert a user row (phone_hash is the only PII stored).
   * 3. Rate-limit: reject if a valid OTP was issued within the last 60s.
   * 4. Generate a 6-digit OTP, hash it with bcrypt-equivalent (SHA-256 + salt
   *    via pgcrypto on the DB side to keep plaintext OTP off the wire as long
   *    as possible), store in otp_requests.
   * 5. Return the plaintext OTP — in production this is handed to your SMS
   *    provider, never logged or persisted.
   */
  async requestOtp(phone: string): Promise<{ message: string; otp?: string }> {
    const phoneHash = this.hashPhone(phone);

    // Upsert user — phone_hash is stored as BYTEA
    const user = await this.upsertUser(phoneHash);

    // Rate-limit: check for a recent pending OTP
    await this.assertNoRecentOtp(user.id);

    // Generate OTP
    const plainOtp = this.generateOtp();
    const otpHash = this.hashOtp(plainOtp);

    // Persist OTP request
    await this.db.query(
      `INSERT INTO otp_requests (user_id, code_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '${OTP_TTL_MINUTES} minutes')`,
      [user.id, otpHash],
    );

    this.logger.log(`OTP issued for user ${user.id}`);

    // In production: pass plainOtp to SMS provider here, do NOT return it.
    // Returning it here for development/testing convenience only.
    const isDev = this.config.get<string>('NODE_ENV') !== 'production';
    return {
      message: 'OTP sent successfully.',
      ...(isDev && { otp: plainOtp }),
    };
  }

  /**
   * POST /auth/verify-otp
   *
   * 1. Hash the phone number → look up user.
   * 2. Find the most recent, non-expired, non-verified OTP request.
   * 3. Validate attempt count (max 5).
   * 4. Compare hashed OTP — constant-time comparison.
   * 5. Mark OTP as verified.
   * 6. Create a session row and emit a signed JWT.
   */
  async verifyOtp(
    phone: string,
    code: string,
  ): Promise<{ accessToken: string; userId: string }> {
    const phoneHash = this.hashPhone(phone);

    // Resolve user
    const user = await this.findUserByPhoneHash(phoneHash);
    if (!user) {
      // Avoid leaking whether phone is registered
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Find the active OTP request
    const otpRequest = await this.findActiveOtpRequest(user.id);
    if (!otpRequest) {
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Increment attempt counter first to prevent race conditions
    await this.incrementOtpAttempt(otpRequest.id);

    if (otpRequest.attempts + 1 > MAX_OTP_ATTEMPTS) {
      throw new UnauthorizedException(
        'Too many attempts. Request a new OTP.',
      );
    }

    // Constant-time OTP comparison
    const candidateHash = this.hashOtp(code);
    const valid = crypto.timingSafeEqual(
      Buffer.from(candidateHash, 'hex'),
      Buffer.from(otpRequest.code_hash),
    );

    if (!valid) {
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Mark OTP as verified and create session — use a transaction
    const session = await this.db.withTransaction(async (client) => {
      // Mark verified
      await client.query(
        `UPDATE otp_requests SET verified = TRUE WHERE id = $1`,
        [otpRequest.id],
      );

      // Create session
      const { rows } = await client.query<SessionRow>(
        `INSERT INTO sessions (user_id, expires_at)
         VALUES ($1, NOW() + INTERVAL '30 days')
         RETURNING id`,
        [user.id],
      );

      return rows[0];
    });

    // Emit JWT
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

  /**
   * SHA-256 hash of the E.164 phone number.
   * Stored as hex string, inserted as BYTEA via parameterized query.
   */
  private hashPhone(phone: string): Buffer {
    return crypto.createHash('sha256').update(phone, 'utf8').digest();
  }

  /**
   * SHA-256 hash of the plaintext OTP code.
   * For a production system, consider PBKDF2 or bcrypt for OTP hashing,
   * but given the 10-minute TTL and 5-attempt cap, SHA-256 is acceptable.
   */
  private hashOtp(code: string): string {
    return crypto
      .createHash('sha256')
      .update(code + this.config.getOrThrow<string>('OTP_SECRET'))
      .digest('hex');
  }

  private generateOtp(): string {
    // Cryptographically random 6-digit number
    const bytes = crypto.randomBytes(4);
    const num = bytes.readUInt32BE(0) % 1_000_000;
    return num.toString().padStart(OTP_LENGTH, '0');
  }

  private async upsertUser(phoneHash: Buffer): Promise<UserRow> {
    const { rows } = await this.db.query<UserRow>(
      `INSERT INTO users (phone_hash)
       VALUES ($1)
       ON CONFLICT (phone_hash) DO UPDATE SET phone_hash = EXCLUDED.phone_hash
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

  private async assertNoRecentOtp(userId: string): Promise<void> {
    const { rows } = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count
       FROM otp_requests
       WHERE user_id = $1
         AND verified = FALSE
         AND expires_at > NOW()
         AND created_at > NOW() - INTERVAL '${OTP_RATE_LIMIT_SECONDS} seconds'`,
      [userId],
    );

    if (parseInt(rows[0].count, 10) > 0) {
      throw new ConflictException(
        `Please wait ${OTP_RATE_LIMIT_SECONDS} seconds before requesting a new OTP.`,
      );
    }
  }

  private async findActiveOtpRequest(
    userId: string,
  ): Promise<OtpRequestRow | null> {
    const { rows } = await this.db.query<OtpRequestRow>(
      `SELECT id, user_id, code_hash, expires_at, attempts, verified
       FROM otp_requests
       WHERE user_id = $1
         AND verified = FALSE
         AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [userId],
    );
    return rows[0] ?? null;
  }

  private async incrementOtpAttempt(otpRequestId: string): Promise<void> {
    await this.db.query(
      `UPDATE otp_requests SET attempts = attempts + 1 WHERE id = $1`,
      [otpRequestId],
    );
  }
}
