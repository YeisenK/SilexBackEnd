import { Module } from '@nestjs/common';
import { MessagesController } from './messages.controller';
import { MessagesService } from './messages.service';
import { EventsModule } from '../events/events.module';
import { MetricsModule } from '../metrics/metrics.module';

@Module({
  imports: [
    EventsModule,
    MetricsModule,
  ],
  controllers: [MessagesController],
  providers: [MessagesService],
  
})
export class MessagesModule {}