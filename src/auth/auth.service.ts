import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './types/auth';
import { LoginDto } from './dto/login.dto';
import bcrypt from 'bcryptjs';
import { ProfileService } from '../profile/profile.service';
import type { Response, Request } from 'express';
import { PrismaService } from '../prisma/prisma.service';
import { clearTokenCookieOptions, setTokenCookieOptions } from './constants/auth';

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
			};

			const tokens = {
				access_token: this.generateAccessToken(payload),
				refresh_token: this.generateRefreshToken(payload),
			};

			const dbToken = await tx.refreshToken.create({
				data: {
					userId: id,
					expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
				},
			});

			res.cookie('refresh', tokens.refresh_token, setTokenCookieOptions);
			res.cookie('refreshId', dbToken.id, setTokenCookieOptions);

			return {
				access_token: tokens.access_token,
				user: {
					id,
					username,
					email,
				},
			};
		});
	}

	async refresh(req: Request, res: Response) {
		const token = req.cookies['refresh'];
		const tokenId = req.cookies['refreshId'];
		if (!token || !tokenId) {
			res.clearCookie('refresh', clearTokenCookieOptions);
			res.clearCookie('refreshId', clearTokenCookieOptions);
			throw new UnauthorizedException('Unauthorized!');
		}

		let payload;
		try {
			payload = this.jwtService.verify<JwtPayload>(token, {
				secret: process.env.JWT_REFRESH_SECRET,
			});
		} catch {
			await this.prisma.refreshToken.delete({
				where: {
					id: tokenId,
				},
			});
			res.clearCookie('refresh', clearTokenCookieOptions);
			res.clearCookie('refreshId', clearTokenCookieOptions);
			throw new UnauthorizedException('Unauthorized!');
		}

		const storedToken = await this.prisma.refreshToken.findUnique({
			where: {
				id: tokenId,
			},
		});

		if (!storedToken || storedToken.userId !== payload.id) {
			await this.prisma.refreshToken.deleteMany({
				where: {
					userId: payload.id,
				},
			});
			res.clearCookie('refresh', clearTokenCookieOptions);
			res.clearCookie('refreshId', clearTokenCookieOptions);
			throw new UnauthorizedException('Session compromised!');
		}

		const tokens = {
			access_token: this.generateAccessToken({ id: payload.id }),
			refresh_token: this.generateRefreshToken({ id: payload.id }),
		};

		const result = await this.prisma.$transaction(async (tx) => {
			await tx.refreshToken.delete({
				where: {
					id: tokenId,
				},
			});
			const newToken = await tx.refreshToken.create({
				data: {
					userId: payload.id,
					expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
				},
			});
			res.cookie('refresh', tokens.refresh_token, setTokenCookieOptions);
			res.cookie('refreshId', newToken.id, setTokenCookieOptions);

			const user = await this.userService.findUserById(payload.id);

			if (!user) return null;

			return {
				access_token: tokens.access_token,
				user,
			};
		});

		if (!result) {
			res.clearCookie('refresh', clearTokenCookieOptions);
			res.clearCookie('refreshId', clearTokenCookieOptions);
			throw new UnauthorizedException('User not found');
		}

		return result;
	}

	async logout(req: Request, res: Response) {
		const tokenId = req.cookies['refreshId'];

		if (!tokenId) {
			res.clearCookie('refresh', clearTokenCookieOptions);
			res.clearCookie('refreshId', clearTokenCookieOptions);
			throw new UnauthorizedException('Unauthorized!');
		}

		await this.prisma.refreshToken.delete({
			where: {
				id: tokenId,
			},
		});

		res.clearCookie('refresh', clearTokenCookieOptions);
		res.clearCookie('refreshId', clearTokenCookieOptions);

		return {
			message: 'Success!',
		};
	}

	private generateAccessToken(payload: JwtPayload) {
		return this.jwtService.sign(payload, {
			secret: process.env.JWT_ACCESS_SECRET,
			expiresIn: '20m',
		});
	}

	private generateRefreshToken(payload: JwtPayload) {
		return this.jwtService.sign(payload, {
			secret: process.env.JWT_REFRESH_SECRET,
			expiresIn: '2d',
		});
	}
}
