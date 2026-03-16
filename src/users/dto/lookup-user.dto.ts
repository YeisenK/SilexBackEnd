import { IsString, Length } from 'class-validator';

export class LookupUserDto {
  @IsString()
  @Length(64, 64)
  phoneHash: string;
}