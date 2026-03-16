import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as path from 'path';
import { DatabaseService } from '../database/database.service';

@Injectable()
export class PushService implements OnModuleInit {
  private readonly logger = new Logger(PushService.name);

  constructor(private readonly db: DatabaseService) {}

  onModuleInit() {
    try {
      const serviceAccountPath = path.resolve(
        process.cwd(),
        'firebase-service-account.json',
      );

      admin.initializeApp({
        credential: admin.credential.cert(serviceAccountPath),
      });

      this.logger.log('Firebase Admin initialized');
    } catch (e) {
      this.logger.error('Failed to initialize Firebase Admin', e);
    }
  }

  async saveFcmToken(userId: string, deviceId: string, fcmToken: string): Promise<void> {
    await this.db.query(
      `UPDATE sessions SET fcm_token = $1
       WHERE user_id = $2 AND device_id = $3 AND revoked_at IS NULL`,
      [fcmToken, userId, deviceId],
    );
  }

  async sendPushNotification(
    recipientId: string,
    title: string,
    body: string,
    data?: Record<string, string>,
  ): Promise<boolean> {
    try {
      const { rows } = await this.db.query(
        `SELECT fcm_token FROM sessions
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND fcm_token IS NOT NULL
         ORDER BY created_at DESC
         LIMIT 1`,
        [recipientId],
      );

      if (rows.length === 0 || !rows[0].fcm_token) {
        return false;
      }

      const token = rows[0].fcm_token;

      await admin.messaging().send({
        token,
        notification: { title, body },
        data: data ?? {},
        android: {
          priority: 'high',
          notification: {
            channelId: 'silex_messages',
            priority: 'high',
            defaultSound: true,
            defaultVibrateTimings: true,
          },
        },
      });

      this.logger.log(`Push sent to user ${recipientId}`);
      return true;
    } catch (e: any) {
      if (e?.code === 'messaging/registration-token-not-registered') {
        // token expired, clean it up
        await this.db.query(
          `UPDATE sessions SET fcm_token = NULL
           WHERE user_id = $1 AND fcm_token IS NOT NULL`,
          [recipientId],
        );
      }
      this.logger.error(`Push failed for user ${recipientId}: ${e?.message}`);
      return false;
    }
  }
}
