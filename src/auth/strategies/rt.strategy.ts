import { PassportStrategy } from '@nestjs/passport'
import { Strategy } from 'passport-jwt'
import { Request } from 'express'
import { ForbiddenException, Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtPayload, JwtPayloadWithRt } from '../types'

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: (req: Request): string | null => {
        return req.cookies?.['refresh_token'] ?? null
      },
      ignoreExpiration: false,
      secretOrKey: config.get<string>('REFRESH_TOKEN_KEY'),
      passReqToCallback: true,
    })
  }

  validate(req: Request, payload: JwtPayload): JwtPayloadWithRt {
    const refreshToken = req.cookies?.['refresh_token']

    if (!refreshToken) {
      throw new ForbiddenException('Refresh token not available')
    }

    return {
      ...payload,
      refreshToken,
    }
  }
}
