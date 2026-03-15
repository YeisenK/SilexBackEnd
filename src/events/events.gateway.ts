import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MetricsService } from '../metrics/metrics.service';


@WebSocketGateway({
  cors: { origin: '*' },
  namespace: '/chat',
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly connections = new Map<string, Socket>();

  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly metrics: MetricsService,
  ) {}

  async handleConnection(client: Socket): Promise<void> {
    try {
      const token = client.handshake.headers.authorization?.split(' ')[1];

      if (!token) {
        client.disconnect();
        return;
      }

      const payload = this.jwt.verify(token, {
        secret: this.config.getOrThrow<string>('JWT_SECRET'),
        audience: 'silex-client',
        issuer: 'silex',
      });

      client.data.userId = payload.sub;
      this.connections.set(payload.sub, client);
      this.metrics.incWsConnections();

      console.log(`[Gateway] User ${payload.sub} connected`);
    } catch {
      client.disconnect();
    }
  }

  handleDisconnect(client: Socket): void {
    const userId = client.data.userId;
    if (userId) {
      this.connections.delete(userId);
      this.metrics.decWsConnections();
      console.log(`[Gateway] User ${userId} disconnected`);
    }
  }

  deliverMessage(recipientId: string, message: any): boolean {
    const socket = this.connections.get(recipientId);
    if (!socket) return false;

    socket.emit('message', message);
    return true;
  }
}