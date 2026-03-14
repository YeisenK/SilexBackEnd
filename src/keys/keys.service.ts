import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { UploadKeysDto } from './dto/upload-keys.dto';

@Injectable()
export class KeysService {
  constructor(private readonly db: DatabaseService) {}


    async uploadKeys(userId: string, dto: UploadKeysDto): Promise<{ message: string }> {
    await this.db.query(
        `INSERT INTO public_keys 
        (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id, one_time_prekeys)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb)
        ON CONFLICT (user_id) 
        DO UPDATE SET
        identity_key      = EXCLUDED.identity_key,
        signed_prekey     = EXCLUDED.signed_prekey,
        signed_prekey_sig = EXCLUDED.signed_prekey_sig,
        signed_prekey_id  = EXCLUDED.signed_prekey_id,
        one_time_prekeys  = EXCLUDED.one_time_prekeys,
        uploaded_at       = NOW()`,
        [
        userId,
        dto.identityKey,
        dto.signedPrekey,
        dto.signedPrekeySignature,
        dto.signedPrekeyId,
        JSON.stringify(dto.oneTimePrekeys),
        ],
    );

    return { message: 'Keys uploaded successfully.' };
    }

    async getKeys(targetUserId: string): Promise<any> {
    const result = await this.db.withTransaction(async (client) => {
        const { rows } = await client.query(
        `SELECT 
            identity_key,
            signed_prekey,
            signed_prekey_sig,
            signed_prekey_id,
            one_time_prekeys -> 0 AS one_time_prekey
        FROM public_keys
        WHERE user_id = $1`,
        [targetUserId],
        );

        if (rows.length === 0) {
        throw new NotFoundException('No keys found for this user.');
        }

        const keyBundle = rows[0];

        if (keyBundle.one_time_prekey !== null) {
        await client.query(
            `UPDATE public_keys
            SET one_time_prekeys = one_time_prekeys - 0
            WHERE user_id = $1`,
            [targetUserId],
        );
        }

        return keyBundle;
    });

    return result;
    }

}

