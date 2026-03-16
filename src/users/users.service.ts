import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';

@Injectable()
export class UsersService {
  constructor(private readonly db: DatabaseService) {}

  async lookupByPhoneHash(phoneHashHex: string): Promise<{ userId: string } | null> {
    const { rows } = await this.db.query(
      `SELECT id FROM users
       WHERE phone_hash = decode($1, 'hex')
         AND deleted_at IS NULL`,
      [phoneHashHex],
    );

    if (rows.length === 0) return null;
    return { userId: rows[0].id };
  }
}