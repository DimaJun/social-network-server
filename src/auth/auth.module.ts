import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '../user/user.module';
import { AuthGuard } from './guard/auth.guard';
import { ProfileModule } from '../profile/profile.module';

@Module({
	imports: [
		UserModule,
		JwtModule.register({
			global: true,
			secret: process.env.JWT_ACCESS_SECRET,
			signOptions: {
				expiresIn: '15m',
			},
		}),
		ProfileModule,
	],
	controllers: [AuthController],
	providers: [AuthService, AuthGuard],
	exports: [AuthGuard],
})
export class AuthModule {}
