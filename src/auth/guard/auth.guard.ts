import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { JwtPayload } from '../types/auth';

@Injectable()
export class AuthGuard implements CanActivate {
	constructor(private jwtService: JwtService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest();
		const token = this.extractTokenFromHeader(request);
		if (!token) {
			throw new UnauthorizedException('Не авторизован!');
		}
		try {
			const payload = await this.jwtService.verifyAsync(token, {
				secret: process.env.JWT_ACCESS_SECRET,
			});
			request.user = payload as JwtPayload;
		} catch {
			throw new UnauthorizedException('Не авторизован!');
		}
		return true;
	}

	private extractTokenFromHeader(req: Request): string | undefined {
		const [type, token] = req.headers.authorization?.split(' ') ?? [];
		return type === 'Bearer' ? token : undefined;
	}
}
