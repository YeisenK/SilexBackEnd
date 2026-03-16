import { Body, Controller, Get, Param, Put, Post, Request, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt.guard';
import { UsersService } from './users.service';
import { LookupUserDto } from './dto/lookup-user.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('lookup')
  async lookup(@Body() dto: LookupUserDto) {
    const result = await this.usersService.lookupByPhoneHash(dto.phoneHash);
    return {
      found: !!result,
      userId: result?.userId ?? null,
      displayName: result?.displayName ?? null,
      avatarBase64: result?.avatarBase64 ?? null,
    };
  }

  @Get('profile/me')
  async getMyProfile(@Request() req: any) {
    const profile = await this.usersService.getProfile(req.user.userId);
    return profile ?? { displayName: null, avatarBase64: null };
  }

  @Get('profile/:userId')
  async getProfile(@Param('userId') userId: string) {
    const profile = await this.usersService.getProfile(userId);
    return profile ?? { displayName: null, avatarBase64: null };
  }

  @Put('profile')
  async updateProfile(@Request() req: any, @Body() dto: UpdateProfileDto) {
    await this.usersService.updateProfile(
      req.user.userId,
      dto.displayName,
      dto.avatarBase64,
    );
    return { success: true };
  }
}