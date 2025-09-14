import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AuthController } from './auth.controller';
import { UsersService } from './users.service';

@Module({
  imports: [],
  controllers: [AppController, AuthController],
  providers: [UsersService],
})
export class AppModule {}
