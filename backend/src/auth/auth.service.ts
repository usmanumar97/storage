import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/auth.dto';
import { JwtPayloadUser } from './auth.interface';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

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

    console.log('plainPassword:', plainPassword);
    console.log('user.hashPassword:', user.passwordHash);
    const ok = await bcrypt.compare(plainPassword, user.passwordHash);
    if (!ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash: _, ...safe } = user;
    return safe;
  }

  async sign(user: JwtPayloadUser) {
    const sub = typeof user._id === 'string' ? user._id : user._id.toString();
    const payload = { sub, email: user.email };
    return { accessToken: this.jwtService.sign(payload) };
  }
}
