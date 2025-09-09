import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get('/healthz')
  health() {
    return { ok: true, service: 'backend', time: new Date().toISOString() };
  }
}
