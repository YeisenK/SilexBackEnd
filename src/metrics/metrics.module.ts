import { Module } from '@nestjs/common';
import { makeCounterProvider, makeGaugeProvider } from '@willsoto/nestjs-prometheus';
import { MetricsService } from './metrics.service';

@Module({
  providers: [
    MetricsService,
    makeCounterProvider({ name: 'silex_otp_requests_total', help: 'Total OTP requests' }),
    makeCounterProvider({ name: 'silex_otp_verified_total', help: 'Total OTPs verified successfully' }),
    makeCounterProvider({ name: 'silex_otp_failed_total', help: 'Total OTP verification failures' }),
    makeCounterProvider({ name: 'silex_messages_sent_total', help: 'Total messages sent' }),
    makeCounterProvider({ name: 'silex_messages_delivered_total', help: 'Total messages delivered in real time' }),
    makeCounterProvider({ name: 'silex_messages_deferred_total', help: 'Total messages deferred (recipient offline)' }),
    makeGaugeProvider({ name: 'silex_ws_connections_active', help: 'Active WebSocket connections' }),
  ],
  exports: [MetricsService],
})
export class MetricsModule {}