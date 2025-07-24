// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/auth.dto';
import { JwtPayloadUser } from './auth.interface';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { Types } from 'mongoose';
import { LocalAuthUser } from './types/jwt-payload';

type JwtUserBase = {
  _id: Types.ObjectId | string;
  email: string;
  tokenVersion: number;
};

const toId = (id: string | Types.ObjectId) =>
  typeof id === 'string' ? id : id.toString();

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  // ---- (legacy) simple access-token flow kept for backward compatibility ----
  async signUp(dto: SignUpDto) {
    const user = await this.userService.create(dto);
    return this.sign(user);
  }

  async signIn(id: string) {
    const user = await this.userService.findOne(id);
    return this.sign(user);
  }

  async validateUser(email: string, plainPassword: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) return null;

    const ok = await bcrypt.compare(plainPassword, user.passwordHash);
    if (!ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash, ...safe } = user;
    return safe;
  }

  async sign(user: JwtPayloadUser) {
    const sub = typeof user._id === 'string' ? user._id : user._id.toString();
    const payload = { sub, email: user.email };
    return { accessToken: this.jwtService.sign(payload) };
  }
  // --------------------------------------------------------------------------

  // ---- Refresh-token implementation ----
  async signTokens(user: JwtUserBase) {
    const userId =
      typeof user._id === 'string' ? user._id : user._id.toString();

    const payload = {
      sub: userId,
      email: user.email,
      tv: user.tokenVersion ?? 0,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_EXPIRES_IN'),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
      expiresIn: this.configService.get<string>('REFRESH_TOKEN_EXPIRES_IN'),
    });

    return { accessToken, refreshToken };
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hash = await bcrypt.hash(refreshToken, 10);
    await this.userService.updateRefreshTokenHash(userId, hash);
  }

  async clearRefreshToken(userId: string) {
    await this.userService.updateRefreshTokenHash(userId, null);
  }

  async revokeAllSessions(userId: string) {
    await this.userService.incrementTokenVersion(userId);
  }

  async login(user: LocalAuthUser) {
    const tokens = await this.signTokens({
      _id: user._id,
      email: user.email,
      tokenVersion: user.tokenVersion ?? 0,
    });

    await this.updateRefreshToken(toId(user._id), tokens.refreshToken);
    return tokens;
  }

  async refreshTokens(userId: string, rawRefreshToken: string) {
    const user = await this.userService.findOneWithSensitive(userId);
    if (!user || !user.refreshTokenHash) {
      throw new UnauthorizedException('No active session');
    }

    const valid = await bcrypt.compare(rawRefreshToken, user.refreshTokenHash);
    if (!valid) {
      await this.revokeAllSessions(userId);
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    const tokens = await this.signTokens({
      _id: user._id,
      email: user.email,
      tokenVersion: user.tokenVersion ?? 0,
    });

    await this.updateRefreshToken(user._id.toString(), tokens.refreshToken);
    return tokens;
  }
}
