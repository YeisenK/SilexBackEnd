import { Module } from '@nestjs/common';
import { EventsGateway } from './events.gateway';
import { AuthModule } from '../auth/auth.module';
import { MetricsModule } from '../metrics/metrics.module';

@Module({
  imports: [
    AuthModule,
    MetricsModule
  ],
  providers: [EventsGateway],
  exports: [EventsGateway],
})
export class EventsModule {}