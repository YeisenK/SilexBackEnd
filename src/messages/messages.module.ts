import { Module } from '@nestjs/common';
import { MessagesController } from './messages.controller';
import { MessagesService } from './messages.service';
import { DatabaseModule } from '../database/database.module';
import { EventsModule } from '../events/events.module';
import { MetricsModule } from '../metrics/metrics.module';
import { PushModule } from '../push/push.module';

@Module({
  imports: [DatabaseModule, EventsModule, MetricsModule, PushModule],
  controllers: [MessagesController],
  providers: [MessagesService],
})
export class MessagesModule {}
