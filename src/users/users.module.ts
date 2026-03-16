import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { DatabaseModule } from '../database/database.module';
import { PushModule } from '../push/push.module';

@Module({
  imports: [DatabaseModule, PushModule],
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
