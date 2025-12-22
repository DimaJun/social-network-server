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

	async getProfilesByUsername(username?: string) {
		const profiles = await this.prisma.profile.findMany({
			where: username?.trim()
				? {
						user: {
							username: {
								contains: username.trim(),
								mode: 'insensitive',
							},
						},
					}
				: undefined,
			select: {
				id: true,
				avatar: true,
				city: true,
				user: {
					select: {
						username: true,
					},
				},
			},
			take: 15,
		});

		return profiles.map((p) => ({
			id: p.id,
			username: p.user.username,
			avatar: p.avatar,
			city: p.city,
		}));
	}
}
