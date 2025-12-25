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
import { setTokenCookieOptions } from './constants/auth';

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
			const { id } = isUserExist;
			const payload = {
				id,
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

			res.cookie('refresh', tokens.refresh_token, setTokenCookieOptions);

			return {
				access_token: tokens.access_token,
				user: payload,
			};
		});
	}

	async refresh(req: Request, res: Response) {
		const token = req.cookies['refresh'];
		if (!token) throw new UnauthorizedException('Unauthorized');

		let payload: JwtPayload;

		try {
			payload = this.jwtService.verify<JwtPayload>(token, {
				secret: process.env.JWT_REFRESH_SECRET,
			});
		} catch {
			throw new UnauthorizedException('Unauthorized!');
		}

		const userTokens = await this.prisma.refreshToken.findMany({
			where: {
				userId: payload.id,
			},
		});

		if (!userTokens.length) {
			throw new UnauthorizedException('Unauthorized!');
		}

		let matchedToken;
		for (const dbToken of userTokens) {
			const isMatch = await bcrypt.compare(token, dbToken.tokenHash);
			if (isMatch) {
				matchedToken = dbToken;
				break;
			}
		}
		if (!matchedToken) {
			throw new UnauthorizedException('Unauthorized!');
		}

		const tokens = {
			access_token: this.generateAccessToken({ id: payload.id }),
			refresh_token: this.generateRefreshToken({ id: payload.id }),
		};

		const hashedRefresh = await bcrypt.hash(tokens.refresh_token, 10);

		await this.prisma.$transaction(async (tx) => {
			await tx.refreshToken.delete({
				where: { id: matchedToken.id },
			});
			await tx.refreshToken.create({
				data: {
					userId: payload.id,
					tokenHash: hashedRefresh,
					expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
				},
			});
		});

		res.cookie('refresh', tokens.refresh_token, setTokenCookieOptions);

		const user = await this.userService.findUserById(payload.id);
		if (!user) {
			throw new UnauthorizedException('Unauthorized!');
		}

		return {
			user,
			access_token: tokens.access_token,
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
