import { Injectable } from '@nestjs/common';
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
}
