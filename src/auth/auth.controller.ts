import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type{Response} from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

	@Post('/register')
	register(@Body() dto: RegisterDto){
	  return this.authService.register(dto);
	}

	@Post('/login')
	async login(@Body() dto: LoginDto, @Res({passthrough: true}) res: Response) {
	  const data = await this.authService.login(dto);

	  res.cookie('refresh', data.tokens.refresh_token, {
		  httpOnly: true,
		  secure: false,
		  sameSite: "strict",
		  maxAge: 2 * 24 * 60 * 60 * 1000,
	  });

	  return {
		  user: data.user,
		  access_token: data.tokens.access_token
	  }
	}
}
