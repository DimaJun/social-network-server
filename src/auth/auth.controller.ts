import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { Response, Request } from 'express';

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
		res.clearCookie('refresh', {
			httpOnly: true,
			secure: false,
			sameSite: 'strict',
			maxAge: 0,
		});

		return {
			message: 'Success!',
		};
	}

	@Get('/refresh')
	@HttpCode(HttpStatus.OK)
	refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
		const refreshToken = req.cookies['refresh'];
		if (!refreshToken) {
			throw new UnauthorizedException('Не авторизован!');
		}

		return this.authService.refresh(refreshToken, res);
	}
}
