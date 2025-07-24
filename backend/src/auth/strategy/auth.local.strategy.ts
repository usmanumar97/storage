import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string) {
    console.log('Breaking here');
    const user = await this.authService.validateUser(email, password);
    console.log('Breaking here 2');
    if (!user) throw new UnauthorizedException('Invalid Credentials');
    return user;
  }
}
