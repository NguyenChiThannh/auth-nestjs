import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { ValidationPipe } from '@nestjs/common'
import * as cookieParser from 'cookie-parser'

async function bootstrap() {
  const PORT = 3000
  const app = await NestFactory.create(AppModule)
  app.useGlobalPipes(new ValidationPipe())
  app.use(cookieParser())
  app.useGlobalPipes(new ValidationPipe())
  await app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Server start at: http://127.0.0.1:${PORT}/`)
  })
}
bootstrap()
