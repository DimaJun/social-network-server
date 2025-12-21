import { Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';

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
}
