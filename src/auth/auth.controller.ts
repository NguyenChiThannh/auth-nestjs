import { User } from '@prisma/client'
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common'

import {
  Public,
  GetCurrentUserId,
  GetCurrentUser,
  Roles,
} from '../common/decorators'
import { AtGuard, RtGuard } from '../common/guards'
import { AuthService } from './auth.service'
import { AuthDto } from './dto'
import { Response } from 'express'
import { RolesGuard } from 'src/common/guards/roles.guard'
import { Role } from 'src/common/types'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // Route public everyone can access
  @Public()
  @HttpCode(HttpStatus.CREATED)
  @Post('register')
  async register(@Body() dto: AuthDto): Promise<string> {
    await this.authService.register(dto)
    return 'Register successful'
  }

  // Route public everyone can access
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() dto: AuthDto, @Res() res: Response): Promise<void> {
    await this.authService.login(dto, res)
    res.send('Login successful')
  }

  // Route everyone who have login can access
  @UseGuards(AtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @GetCurrentUserId() userId: number,
    @Res() res: Response,
  ): Promise<void> {
    await this.authService.logout(userId, res)
    res.send('Logout successful')
  }

  // Route every who have Refresh Token available can access
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
    @Res() res: Response,
  ): Promise<void> {
    await this.authService.refreshTokens(userId, refreshToken, res)
    res.send('Get new access token successful')
  }

  // Route every who is Admin can access
  @UseGuards(AtGuard, RolesGuard)
  @Roles(Role.Admin)
  @HttpCode(HttpStatus.OK)
  @Get('users')
  async getAllUser(): Promise<User[]> {
    return await this.authService.getAllUser()
  }

  // Route every who is Admin can access
  @UseGuards(AtGuard, RolesGuard)
  @Roles(Role.Admin)
  @HttpCode(HttpStatus.OK)
  @Delete('user/:id')
  async deleteUser(@Param('id', ParseIntPipe) userId: number): Promise<string> {
    await this.authService.deleteUser(userId)
    return 'Delete user successful'
  }

  // Route every who is Admin and User can access
  @UseGuards(AtGuard, RolesGuard)
  @Roles(Role.User, Role.Admin)
  @HttpCode(HttpStatus.OK)
  @Post('user/:id')
  async getInfo(@Param('id', ParseIntPipe) userId: number): Promise<User> {
    return await this.authService.getInfo(userId)
  }

  @Get('admin')
  async createAdmin(): Promise<boolean> {
    return await this.authService.createAdmin()
  }
}
