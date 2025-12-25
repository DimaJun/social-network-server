import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { Response, Request } from 'express';
import { clearTokenCookieOptions } from './constants/auth';

@Controller('auth')
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Post('/register')
	@HttpCode(HttpStatus.OK)
	async signup(@Body() dto: RegisterDto) {
		return await this.authService.signup(dto);
	}

	@Post('/login')
	@HttpCode(HttpStatus.OK)
	async signin(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
		return await this.authService.signin(dto, res);
	}

	@Post('/logout')
	@HttpCode(HttpStatus.OK)
	logout(@Res({ passthrough: true }) res: Response) {
		res.clearCookie('refresh', clearTokenCookieOptions);

		return {
			message: 'Success!',
		};
	}

	@Post('/refresh')
	@HttpCode(HttpStatus.OK)
	refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
		return this.authService.refresh(req, res);
	}
}
