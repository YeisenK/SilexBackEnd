import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';

@Injectable()
export class UsersService {
  constructor(private readonly db: DatabaseService) {}

  async lookupByPhoneHash(
    phoneHashHex: string,
  ): Promise<{ userId: string; displayName: string | null; avatarBase64: string | null } | null> {
    const { rows } = await this.db.query(
      `SELECT id, display_name, avatar_base64 FROM users
       WHERE phone_hash = decode($1, 'hex')
         AND deleted_at IS NULL`,
      [phoneHashHex],
    );

    if (rows.length === 0) return null;
    return {
      userId: rows[0].id,
      displayName: rows[0].display_name,
      avatarBase64: rows[0].avatar_base64,
    };
  }

  async getProfile(
    userId: string,
  ): Promise<{ displayName: string | null; avatarBase64: string | null } | null> {
    const { rows } = await this.db.query(
      `SELECT display_name, avatar_base64 FROM users
       WHERE id = $1 AND deleted_at IS NULL`,
      [userId],
    );

    if (rows.length === 0) return null;
    return {
      displayName: rows[0].display_name,
      avatarBase64: rows[0].avatar_base64,
    };
  }

  async updateProfile(
    userId: string,
    displayName?: string,
    avatarBase64?: string,
  ): Promise<void> {
    const fields: string[] = [];
    const values: any[] = [];
    let idx = 1;

    if (displayName !== undefined) {
      fields.push(`display_name = $${idx++}`);
      values.push(displayName);
    }

    if (avatarBase64 !== undefined) {
      fields.push(`avatar_base64 = $${idx++}`);
      values.push(avatarBase64);
    }

    if (fields.length === 0) return;

    values.push(userId);
    await this.db.query(
      `UPDATE users SET ${fields.join(', ')} WHERE id = $${idx}`,
      values,
    );
  }
}