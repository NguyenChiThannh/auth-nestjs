import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Strategy } from 'passport-jwt'
import { JwtPayload } from '../types'
import { PassportStrategy } from '@nestjs/passport'
import { Request } from 'express'

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: (req: Request): string | null => {
        return req.cookies?.['access_token'] ?? null
      },
      ignoreExpiration: false,
      secretOrKey: config.get<string>('ACCESS_TOKEN_KEY'),
    })
  }

  async validate(payload: JwtPayload) {
    return payload
  }
}
