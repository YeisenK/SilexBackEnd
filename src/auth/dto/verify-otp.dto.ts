import { IsPhoneNumber, IsString, Length } from 'class-validator';

export class VerifyOtpDto {
  @IsPhoneNumber()
  phone: string;

  /** 6-digit numeric OTP submitted by the user. */
  @IsString()
  @Length(6, 6)
  code: string;
}
