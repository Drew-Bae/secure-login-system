import { Body, Controller, HttpException, HttpStatus, Post } from '@nestjs/common';
import { UsersService } from './users.service';
import * as bcrypt from 'bcrypt';

@Controller('auth')
export class AuthController {
  constructor(private readonly users: UsersService) {}

  @Post('signup')
  async signup(@Body() body: { email: string; password: string }) {
    if (!body?.email || !body?.password) {
      throw new HttpException('Email and password required', HttpStatus.BAD_REQUEST);
    }
    const existing = await this.users.findByEmail(body.email);
    if (existing) throw new HttpException('Email in use', HttpStatus.CONFLICT);
    const user = await this.users.create(body.email, body.password);
    return { id: user.id, email: user.email };
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    const user = await this.users.findByEmail(body.email);
    if (!user || !user.passwordHash) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
    const ok = await bcrypt.compare(body.password, user.passwordHash);
    if (!ok) throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    return { ok: true, user: { id: user.id, email: user.email } };
  }
}
