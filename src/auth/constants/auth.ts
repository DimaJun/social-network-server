import { CookieOptions } from 'express';

export const setTokenCookieOptions: CookieOptions = {
	httpOnly: true,
	secure: false,
	sameSite: 'strict',
	maxAge: 2 * 24 * 60 * 60 * 1000,
};

export const clearTokenCookieOptions: CookieOptions = {
	httpOnly: true,
	secure: false,
	sameSite: 'strict',
	maxAge: 0,
};
