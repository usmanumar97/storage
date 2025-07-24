import { Controller, Post, Body, UseGuards, Res, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/auth.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ConfigService } from '@nestjs/config';
import { UserService } from 'src/user/user.service';
import { AuthGuard } from '@nestjs/passport';
import { Response, Request } from 'express';
import {
  AccessJwtPayload,
  RefreshRequestUser,
  LocalAuthUser,
} from './types/jwt-payload';

type RequestWithUser<T> = Request & { user: T };

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  @Post('signup')
  async signup(
    @Body() dto: SignUpDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.userService.create(dto);

    // Map the Mongoose doc to the LocalAuthUser shape expected by authService.login
    const localUser: LocalAuthUser = {
      _id: user._id,
      email: user.email,
      tokenVersion: user.tokenVersion ?? 0,
    };

    const tokens = await this.authService.login(localUser);
    this.setRefreshCookie(res, tokens.refreshToken);
    return { accessToken: tokens.accessToken };
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Req() req: RequestWithUser<LocalAuthUser>,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.login(req.user);
    this.setRefreshCookie(res, tokens.refreshToken);
    return { accessToken: tokens.accessToken };
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  async refresh(
    @Req() req: RequestWithUser<RefreshRequestUser>,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { userId, refreshToken } = req.user;
    const tokens = await this.authService.refreshTokens(userId, refreshToken);
    this.setRefreshCookie(res, tokens.refreshToken);
    return { accessToken: tokens.accessToken };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @Req() req: RequestWithUser<AccessJwtPayload>,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.clearRefreshToken(req.user.userId);
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
    return { success: true };
  }

  private setRefreshCookie(res: Response, token: string) {
    const maxAgeMs = this.ms(
      this.configService.get<string>('REFRESH_TOKEN_EXPIRES_IN'),
    );
    res.cookie('refreshToken', token, {
      httpOnly: true,
      secure: true, // true in prod
      sameSite: 'strict',
      path: '/auth/refresh',
      maxAge: maxAgeMs,
    });
  }

  private ms(time: string) {
    const match = /^(\d+)([smhd])$/.exec(time);
    if (!match) return 0;
    const n = parseInt(match[1], 10);
    const unit = match[2];
    const multipliers = { s: 1000, m: 6e4, h: 3.6e6, d: 8.64e7 };
    return n * multipliers[unit as keyof typeof multipliers];
  }
}
