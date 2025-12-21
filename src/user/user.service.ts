import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import bcrypt from 'bcryptjs';
import { Prisma } from '../../generated/prisma/client';

@Injectable()
export class UserService {
	constructor(private prisma: PrismaService) {}

	async createUser(dto: CreateUserDto) {
		const isUserExist = await this.prisma.user.findFirst({
			where: {
				OR: [{ email: dto.email }, { username: dto.username }],
			},
		});

		if (isUserExist) {
			if (isUserExist.email === dto.email) {
				throw new ConflictException('Пользователь с такой почтой уже зарегистрирован!');
			}
			if (isUserExist.username === dto.username) {
				throw new ConflictException('Пользоваватель с таким ником уже зарегистрирован!');
			}
		}

		const hashedPassword = await bcrypt.hash(dto.password, 10);

		try {
			return await this.prisma.user.create({
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

	async findUserByEmail(email: string) {
		return this.prisma.user.findUnique({
			where: { email },
		});
	}

	async findUserById(id: string) {
		return this.prisma.user.findUnique({
			where: { id },
		});
	}
}
