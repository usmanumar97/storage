import { Types } from 'mongoose';

export type AccessJwtPayload = {
  userId: string;
  email: string;
  tv: number;
};

export type RefreshRequestUser = AccessJwtPayload & {
  refreshToken: string;
};

export type LocalAuthUser = {
  _id: string | Types.ObjectId;
  email: string;
  tokenVersion: number;
};
