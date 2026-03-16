import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt.guard';
import { UsersService } from './users.service';
import { LookupUserDto } from './dto/lookup-user.dto';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('lookup')
  async lookup(@Body() dto: LookupUserDto) {
    const result = await this.usersService.lookupByPhoneHash(dto.phoneHash);
    return { found: !!result, userId: result?.userId ?? null };
  }
}