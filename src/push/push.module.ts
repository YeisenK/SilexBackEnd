import { Module } from '@nestjs/common';
import { PushService } from './push.service';
import { DatabaseModule } from '../database/database.module';

@Module({
  imports: [DatabaseModule],
  providers: [PushService],
  exports: [PushService],
})
export class PushModule {}
