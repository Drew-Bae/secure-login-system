import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

@Injectable()
export class UsersService {
  async create(email: string, password: string) {
    const passwordHash = await bcrypt.hash(password, 12);
    return prisma.user.create({ data: { email, passwordHash } });
  }
  async findByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }
}
