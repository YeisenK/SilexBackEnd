import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from '../database/database.service'

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private readonly config: ConfigService,
        private readonly db: DatabaseService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), //Extract token
            igonreExpiration: false,
            secretOrKey: config.getOrThrow<string>('JWT_SECRET'),
            audience: 'silex-client',
            issuer: 'silex',
        });
    }

    //check if the token is 'Non-expired' and the signature is valid
    async validate(payload: {sub: string; sid: string}) {
        const { rows } = await this.db.query(
            'SELECT id, user_id, revoked_at, expires_at FROM sessions WHERE id = $1 AND revoked_at IS null AND expires_at > NOW()',
            [payload.sid],
        );

        if(rows.length === 0) {
            throw new UnauthorizedException('Session either expired or revoked.');
        }

        return { userId: payload.sub, sessionId: payload.sid};
    }



}