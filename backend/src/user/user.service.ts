import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from './entities/user.entity';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async create(dto: CreateUserDto) {
    const hash = await bcrypt.hash(dto.password, 10);

    try {
      const user = new this.userModel({
        ...dto,
        passwordHash: hash,
      });
      return (await user.save()).toJSON();
    } catch (err) {
      if (err.code === 11000) {
        throw new BadRequestException('Email already exists!');
      }
      throw err;
    }
  }

  async findAll() {
    return await this.userModel.find().select('-passwordHash').lean();
  }

  async findOne(id: string) {
    const user = await this.userModel
      .findById(id)
      .select('-passwordHash')
      .lean();

    if (!user) {
      throw new NotFoundException('User Not Found');
    }
    return user;
  }

  async findByEmail(email: string) {
    const user = await this.userModel
      .findOne({ email })
      .select('+email +passwordHash')
      .lean();

    if (!user) {
      throw new NotFoundException('User Not Found');
    }
    return user;
  }

  async update(id: string, dto: UpdateUserDto) {
    const updateData: Partial<User> = {};
    if (dto.email) updateData.email = dto.email;
    if (dto.password)
      updateData.passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.userModel
      .findByIdAndUpdate(id, updateData, {
        new: true,
      })
      .select('-passwordHash')
      .lean();

    if (!user) throw new NotFoundException('User Not Found');
    return user;
  }

  async remove(id: string) {
    const user = await this.userModel.findByIdAndDelete(id);
    if (!user) throw new NotFoundException('User Not Found');
    return { message: `User with email ${user.email} has been deleted.` };
  }

  // Refresh Token Helper Methods
  async findOneWithSensitive(id: string) {
    return this.userModel
      .findById(id)
      .select('+passwordHash +refreshTokenHash +tokenVersion')
      .exec();
  }

  async updateRefreshTokenHash(userId: string, hash: string | null) {
    await this.userModel.updateOne(
      { _id: new Types.ObjectId(userId) },
      { $set: { refreshTokenHash: hash } },
    );
  }

  async incrementTokenVersion(userId: string) {
    await this.userModel.updateOne(
      { _id: new Types.ObjectId(userId) },
      { $inc: { tokenVersion: 1 }, $set: { refreshTokenHash: null } },
    );
  }
}
