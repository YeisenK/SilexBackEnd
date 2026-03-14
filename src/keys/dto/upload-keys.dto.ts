import { IsArray, IsInt, IsString, Min, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class OneTimePrekey {
  @IsInt()
  @Min(1)
  id: number;

  @IsString()
  key: string;
}

export class UploadKeysDto {
  @IsString()
  identityKey: string;

  @IsString()
  signedPrekey: string;

  @IsString()
  signedPrekeySignature: string;

  @IsInt()
  @Min(1)
  signedPrekeyId: number;

  @IsArray()
  @ValidateNested({ each: true }) // validates all the elemts on the array
  @Type(() => OneTimePrekey)
  oneTimePrekeys: OneTimePrekey[];
}