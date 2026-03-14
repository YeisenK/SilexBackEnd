import { Controller, Get, Post, Body, Param, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt.guard';
import { KeysService } from './keys.service';
import { UploadKeysDto } from './dto/upload-keys.dto';

@Controller('keys')
@UseGuards(JwtAuthGuard)
export class KeysController {
  constructor(private readonly keysService: KeysService) {}

  @Post()
  uploadKeys(@Request() req: any, @Body() dto: UploadKeysDto) {
    return this.keysService.uploadKeys(req.user.userId, dto);
  }

  @Get(':userId')
  getKeys(@Param('userId') userId: string) {
    return this.keysService.getKeys(userId);
  }
}