import { Injectable } from '@nestjs/common';
import { Counter, Gauge, Histogram } from 'prom-client';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { MetricsService } from '../metrics/metrics.service';

@Injectable()
export class MetricsService {
  constructor(
    @InjectMetric('silex_otp_requests_total')
    private readonly otpRequestsCounter: Counter<string>,

    @InjectMetric('silex_otp_verified_total')
    private readonly otpVerifiedCounter: Counter<string>,

    @InjectMetric('silex_otp_failed_total')
    private readonly otpFailedCounter: Counter<string>,

    @InjectMetric('silex_messages_sent_total')
    private readonly messagesSentCounter: Counter<string>,

    @InjectMetric('silex_messages_delivered_total')
    private readonly messagesDeliveredCounter: Counter<string>,

    @InjectMetric('silex_messages_deferred_total')
    private readonly messagesDeferredCounter: Counter<string>,

    @InjectMetric('silex_ws_connections_active')
    private readonly wsConnectionsGauge: Gauge<string>,
    
    private readonly metrics: MetricsService,
  ) {}

  incOtpRequests(): void { this.otpRequestsCounter.inc(); }
  incOtpVerified(): void { this.otpVerifiedCounter.inc(); }
  incOtpFailed(): void { this.otpFailedCounter.inc(); }
  incMessagesSent(): void { this.messagesSentCounter.inc(); }
  incMessagesDelivered(): void { this.messagesDeliveredCounter.inc(); }
  incMessagesDeferred(): void { this.messagesDeferredCounter.inc(); }
  incWsConnections(): void { this.wsConnectionsGauge.inc(); }
  decWsConnections(): void { this.wsConnectionsGauge.dec(); }
}