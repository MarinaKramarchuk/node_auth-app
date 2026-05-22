import { Router } from 'express';
import { authController } from './auth.controller.js';
import { authMiddleware } from '../middlewares/auth.middleware.js';

export const authRouter = Router();

authRouter.post('/register', authController.register);
authRouter.post('/login', authController.login);
authRouter.post('/activate/:email/:token', authController.activate);
authRouter.post('/refresh', authController.refresh);
authRouter.post('/logout', authController.logout);

// Нові маршрути для пароля
authRouter.post('/forgot-password', authController.forgotPassword);
authRouter.post('/reset-password', authController.resetPassword);

// Нові маршрути для профілю (захищені мідлварою)
authRouter.patch('/profile', authMiddleware, authController.updateProfile);
authRouter.patch('/profile/password', authMiddleware, authController.updatePassword);
