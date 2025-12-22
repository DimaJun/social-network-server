import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
import { ProfileService } from './profile.service';
import type { RequestWithUser } from './types/profile';
import { AuthGuard } from '../auth/guard/auth.guard';

@Controller('profile')
export class ProfileController {
	constructor(private readonly profileService: ProfileService) {}

	@UseGuards(AuthGuard)
	@Get('/my')
	async getMyProfile(@Req() req: RequestWithUser) {
		return this.profileService.getProfileByUserId(req.user.id);
	}

	@UseGuards(AuthGuard)
	@Get()
	async getProfilesByQuery(@Query('search') search?: string) {
		return this.profileService.getProfilesByUsername(search);
	}
}
