import { IsString } from 'class-validator';

export class RegisterTokenDto {
  @IsString()
  fcmToken: string;

  @IsString()
  deviceId: string;
}
