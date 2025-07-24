import { IsEmail, IsString } from 'class-validator';

export class ValidateUser {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}

export class SignUpDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}
