import { Types } from 'mongoose';

export interface JwtPayloadUser {
  _id: string | Types.ObjectId;
  email: string;
}
