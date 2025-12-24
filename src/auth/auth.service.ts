import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './types/auth';
import { LoginDto } from './dto/login.dto';
import bcrypt from 'bcryptjs';
import { ProfileService } from '../profile/profile.service';
import type { Response } from 'express';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
	constructor(
		private readonly prisma: PrismaService,
		private readonly userService: UserService,
		private readonly jwtService: JwtService,
		private readonly profileService: ProfileService,
	) {}

	async signup(dto: RegisterDto) {
		await this.userService.checkUserUnique(dto);

		return this.prisma.$transaction(async (tx) => {
			const user = await this.userService.createUser(dto, tx);
			if (user) {
				await this.profileService.createProfile(user.id, tx);
				const { password, ...withoutPassword } = user;
				return withoutPassword;
			}
		});
	}

	async signin(dto: LoginDto, res: Response) {
		return this.prisma.$transaction(async (tx) => {
			const isUserExist = await tx.user.findUnique({
				where: { email: dto.email },
			});
			if (!isUserExist) {
				throw new UnauthorizedException(`Пользователя с почтой: ${dto.email} не существует!`);
			}
			const isPasswordsMatch = await bcrypt.compare(dto.password, isUserExist.password);
			if (!isPasswordsMatch) {
				throw new UnauthorizedException('Неправильный пароль!');
			}
			const { id, username, email } = isUserExist;
			const payload = {
				id,
				username,
				email,
			};

			const tokens = {
				access_token: this.generateAccessToken(payload),
				refresh_token: this.generateRefreshToken(payload),
			};

			const hashedRefresh = await bcrypt.hash(tokens.refresh_token, 10);
			await tx.refreshToken.create({
				data: {
					userId: id,
					tokenHash: hashedRefresh,
					expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
				},
			});

			res.cookie('refresh', tokens.refresh_token, {
				httpOnly: true,
				secure: false,
				sameSite: 'strict',
				maxAge: 2 * 24 * 60 * 60 * 1000,
			});

			return {
				access_token: tokens.access_token,
				user: payload,
			};
		});
	}

	async refresh(refreshToken: string, res: Response) {
		let payload: JwtPayload;

		try {
			payload = this.jwtService.verify(refreshToken, {
				secret: process.env.JWT_REFRESH_SECRET,
			});
		} catch {
			res.clearCookie('refresh', {
				httpOnly: true,
				secure: false,
				sameSite: 'strict',
				maxAge: 0,
			});
			throw new UnauthorizedException('Refresh token expired or invalid');
		}

		const user = await this.userService.findUserById(payload.id);

		if (!user) throw new UnauthorizedException('Не авторизован!');
		const { id, email, username } = user;
		const tokens = {
			access_token: this.generateAccessToken({ id, username, email }),
			refresh_token: this.generateRefreshToken({ id, username, email }),
		};

		res.cookie('refresh', tokens.refresh_token, {
			httpOnly: true,
			secure: false,
			sameSite: 'strict',
			maxAge: 2 * 24 * 60 * 60 * 1000,
		});

		return {
			access_token: tokens.access_token,
			user: {
				id,
				username,
				email,
			},
		};
	}

	private generateAccessToken(payload: JwtPayload) {
		return this.jwtService.sign(payload, {
			secret: process.env.JWT_ACCESS_SECRET,
			expiresIn: '15m',
		});
	}

	private generateRefreshToken(payload: JwtPayload) {
		return this.jwtService.sign(payload, {
			secret: process.env.JWT_REFRESH_SECRET,
			expiresIn: '2d',
		});
	}
}
