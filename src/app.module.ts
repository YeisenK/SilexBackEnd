import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { DatabaseModule } from './database/database.module';
import { EventsModule } from './events/events.module';
import { KeysModule } from './keys/keys.module';
import { MessagesModule } from './messages/messages.module';


@Module({
  imports: [
    // Loads .env and makes ConfigService available globally
    ConfigModule.forRoot({ isGlobal: true }),
    DatabaseModule,
    AuthModule,
    KeysModule,
    EventsModule,
    MessagesModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
