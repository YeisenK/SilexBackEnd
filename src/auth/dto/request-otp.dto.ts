import { IsPhoneNumber, IsString, Length, Matches } from 'class-validator';

export class RequestOtpDto {
  /**
   * E.164 phone number format: +1234567890
   * The raw number is never stored — only its SHA-256 hash reaches the DB.
   */
  @IsPhoneNumber()
  phone: string;
}
