import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import * as bcrypt from 'bcrypt'
import { PrismaService } from '../prisma/prisma.service'
import { AuthDto } from './dto'
import { JwtPayload, TokenKeys } from './types'
import { Response } from 'express'
import { User } from '@prisma/client'

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async register(dto: AuthDto): Promise<boolean> {
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    })

    if (existingUser) throw new BadRequestException('User already exists ')

    const hashPassword = await bcrypt.hash(dto.password, 10)
    await this.prisma.user.create({
      data: {
        email: dto.email,
        hashPassword,
      },
    })
    return true
  }

  async login(dto: AuthDto, res: Response): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    })
    if (!user) throw new ForbiddenException('User not found')

    const passwordMatches = await bcrypt.compare(
      dto.password,
      user.hashPassword,
    )
    if (!passwordMatches) throw new ForbiddenException('Password is wrong')

    const [access_token, refresh_token] = await Promise.all([
      this.generateTokens(user.id, user.roles, 'ACCESS_TOKEN_KEY'),
      this.generateTokens(user.id, user.roles, 'REFRESH_TOKEN_KEY'),
    ])
    await this.updateRtHash(user.id, refresh_token)
    res.cookie('access_token', access_token, {
      httpOnly: true,
      secure: true,
      path: '/',
      sameSite: 'strict',
    })
    res.cookie('refresh_token', refresh_token, {
      httpOnly: true,
      secure: true,
      path: '/',
      sameSite: 'strict',
    })
    return true
  }

  async logout(userId: number, res: Response): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRefreshToken: {
          not: null,
        },
      },
      data: {
        hashedRefreshToken: null,
      },
    })
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
    return true
  }

  async refreshTokens(
    userId: number,
    refreshToken: string,
    res: Response,
  ): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    })
    if (!user || !user.hashedRefreshToken)
      throw new ForbiddenException('Access Denied')

    const rtMatches = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken,
    )
    if (!rtMatches) throw new ForbiddenException('Access Denied')

    const [access_token, refresh_token] = await Promise.all([
      this.generateTokens(user.id, user.roles, 'ACCESS_TOKEN_KEY'),
      this.generateTokens(user.id, user.roles, 'REFRESH_TOKEN_KEY'),
    ])
    await this.updateRtHash(user.id, refresh_token)
    res.cookie('access_token', access_token, {
      httpOnly: true,
      secure: true,
      path: '/',
      sameSite: 'strict',
    })
    res.cookie('refresh_token', refresh_token, {
      httpOnly: true,
      secure: true,
      path: '/',
      sameSite: 'strict',
    })
    return true
  }

  async updateRtHash(userId: number, refreshToken: string): Promise<void> {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 8)
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken,
      },
    })
  }

  async generateTokens(
    userId: number,
    roles: string,
    typeTokens: TokenKeys,
  ): Promise<string> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      roles,
    }
    const token = await this.jwtService.signAsync(jwtPayload, {
      secret: this.config.get<string>(typeTokens),
      expiresIn: typeTokens === 'ACCESS_TOKEN_KEY' ? '15m' : '7d',
    })

    return token
  }

  async getAllUser(): Promise<User[]> {
    return await this.prisma.user.findMany()
  }

  async deleteUser(userId: number): Promise<boolean> {
    await this.prisma.user.delete({
      where: {
        id: userId,
      },
    })
    return true
  }

  async getInfo(userId: number): Promise<User> {
    return await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    })
  }

  async createAdmin(): Promise<boolean> {
    const hashPassword = await bcrypt.hashSync('123', 10)
    await this.prisma.user.create({
      data: {
        email: 'thanh1@gmail.com',
        hashPassword,
        roles: 'admin',
      },
    })
    return true
  }
}
