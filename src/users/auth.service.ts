import {
  BadRequestException,
  Injectable,
  NotFoundException,
  Post,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';

const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService {
  constructor(private userService: UsersService) {}

  @Post()
  async signup(email: string, password: string) {
    // see if email is in use
    const users = await this.userService.find(email);
    if (users.length) {
      throw new BadRequestException('Email in use');
    }
    // generate a salt
    const salt = randomBytes(8).toString('hex');

    // hash the password together with the salt
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    // join the hashed results and the salt together
    const result = salt + '.' + hash.toString('hex');

    // create a new user
    const user = await this.userService.create(email, result);

    // return the user
    return user;
  }

  @Post()
  async signin(email: string, password: string) {
    const [user] = await this.userService.find(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const [salt, storedHash] = user.password.split('.');
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    if (hash.toString('hex') !== storedHash) {
      throw new BadRequestException('Wrong email address or password');
    }

    return user;
  }
}
