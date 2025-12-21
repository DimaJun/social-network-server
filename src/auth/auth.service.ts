import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './types/auth';
import { LoginDto } from './dto/login.dto';
import bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
	constructor(
		private readonly userService: UserService,
		private readonly jwtService: JwtService,
	) {}

	async register(dto: RegisterDto) {
		const user = await this.userService.createUser(dto);

		if (user) {
			const { password, ...withoutPassword } = user;
			return withoutPassword;
		}
	}

	async login(dto: LoginDto) {
		const isUserExist = await this.userService.findUserByEmail(dto.email);
		if(!isUserExist) {
			throw new UnauthorizedException(`Пользователя с почтой: ${dto.email} не существует!`);
		}
		const isPasswordsMatch = await bcrypt.compare(dto.password, isUserExist.password);
		if(!isPasswordsMatch) {
			throw new UnauthorizedException('Неправильный пароль!')
		}
		const {id, username, email} = isUserExist;
		const payload = {
			id,
			username,
			email
		}

		return {
			user: payload,
			tokens: {
				access_token: this.generateAccessToken(payload),
				refresh_token: this.generateRefreshToken(payload)
			}
		}
	}

	generateAccessToken(payload: JwtPayload) {
		return this.jwtService.sign(payload, {
			secret: process.env.JWT_ACCESS_SECRET,
			expiresIn: '15m'
		})
	}

	generateRefreshToken(payload: JwtPayload) {
		return this.jwtService.sign(payload, {
			secret: process.env.JWT_REFRESH_SECRET,
			expiresIn: '2d',
		});
	}
}
