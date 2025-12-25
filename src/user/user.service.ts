import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import bcrypt from 'bcryptjs';
import { Prisma } from '../../generated/prisma/client';

@Injectable()
export class UserService {
	constructor(private prisma: PrismaService) {}

	async createUser(dto: CreateUserDto, tx?: Prisma.TransactionClient) {
		const client = tx ?? this.prisma;
		const hashedPassword = await bcrypt.hash(dto.password, 10);

		try {
			return await client.user.create({
				data: {
					email: dto.email,
					username: dto.username,
					password: hashedPassword,
				},
			});
		} catch (e) {
			if (e instanceof Prisma.PrismaClientKnownRequestError) {
				if (e.code === 'P2002') {
					throw new ConflictException('Пользователь с такой почтой или ником уже зарегистрирован!');
				}
			}
		}
	}

	async checkUserUnique(dto: CreateUserDto) {
		const existingUser = await this.prisma.user.findFirst({
			where: {
				OR: [{ email: dto.email }, { username: dto.username }],
			},
		});

		if (!existingUser) return;

		if (existingUser.email === dto.email) {
			throw new ConflictException('Пользователь с такой почтой уже зарегистрирован!');
		}

		if (existingUser.username === dto.username) {
			throw new ConflictException('Пользователь с таким ником уже зарегистрирован!');
		}
	}

	async findUserById(id: string) {
		return this.prisma.user.findUnique({
			where: { id },
			select: {
				email: true,
				username: true,
				id: true,
			},
		});
	}
}
