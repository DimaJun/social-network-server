import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ProfileService {
	constructor(private readonly prisma: PrismaService) {}

	async createProfile(userId: string) {
		return this.prisma.profile.create({
			data: {
				userId,
			},
		});
	}

	async getProfileByUserId(userId?: string) {
		if (!userId) {
			throw new UnauthorizedException('Не авторизован!');
		}
		const profile = await this.prisma.profile.findUnique({
			where: {
				userId,
			},
			include: {
				user: {
					select: {
						username: true,
					},
				},
			},
		});

		if (!profile) return null;

		return {
			...profile,
			username: profile.user.username,
			user: undefined,
		};
	}
}
