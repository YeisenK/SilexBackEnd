import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { EventsGateway } from '../events/events.gateway';
import { MetricsService } from '../metrics/metrics.service';
import { SendMessageDto } from './dto/send-message.dto';

@Injectable()
export class MessagesService {
  constructor(
    private readonly db: DatabaseService,
    private readonly gateway: EventsGateway,
    private readonly metrics: MetricsService,
  ) {}

  async sendMessage(senderId: string, dto: SendMessageDto): Promise<{ delivered: boolean; messageId: string }> {
    const { rows } = await this.db.query(
      `INSERT INTO messages
        (sender_id, recipient_id, ratchet_key, prev_counter, msg_counter, ciphertext, iv, message_type, sender_identity_key, used_otpk_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [
        senderId,
        dto.recipientId,
        dto.ratchetKey,
        dto.prevCounter,
        dto.msgCounter,
        dto.ciphertext,
        dto.iv,
        dto.messageType,
        dto.senderIdentityKey,
        dto.usedOtpkId ?? null,
      ],
    );

    const messageId = rows[0].id;

    this.metrics.incMessagesSent();

    const delivered = this.gateway.deliverMessage(dto.recipientId, {
      messageId,
      senderId,
      ratchetKey: dto.ratchetKey,
      prevCounter: dto.prevCounter,
      msgCounter: dto.msgCounter,
      ciphertext: dto.ciphertext,
      iv: dto.iv,
      messageType: dto.messageType,
      senderIdentityKey: dto.senderIdentityKey,
      usedOtpkId: dto.usedOtpkId ?? null,
    });

    if (delivered) {
      this.metrics.incMessagesDelivered();
    } else {
      this.metrics.incMessagesDeferred();
    }

    return { delivered, messageId };
  }

  async getPendingMessages(userId: string): Promise<any[]> {
    const { rows } = await this.db.query(
      `SELECT
         id,
         sender_id,
         ratchet_key,
         prev_counter,
         msg_counter,
         ciphertext,
         iv,
         message_type,
         sender_identity_key,
         used_otpk_id,
         created_at
       FROM messages
       WHERE recipient_id = $1
         AND delivery_status = 'pending'
         AND expires_at > NOW()
       ORDER BY created_at ASC`,
      [userId],
    );

    return rows;
  }
}