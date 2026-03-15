import { IsIn, IsInt, IsString, IsUUID, Min } from 'class-validator';

export class SendMessageDto {
  @IsUUID()
  recipientId: string;

  @IsString()
  ratchetKey: string;

  @IsInt()
  @Min(0)
  prevCounter: number;

  @IsInt()
  @Min(0)
  msgCounter: number;

  @IsString()
  ciphertext: string;

  @IsString()
  iv: string;

  @IsIn(['text', 'media_ref'])
  messageType: 'text' | 'media_ref';
}