import { User } from "../models/user.models.js";
import { asyncHandler } from "../utils/async_handler.js";
import { ApiError } from "../utils/api_error.js";
import jwt from "jsonwebtoken";
export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new ApiError(401, "UnAuthorized Request");
  }
  try {
    const decodeToken = await jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET,
    );
    const user = await User.findById(decodeToken?._id).select(
      "-password -emailVerificationToken -emailVerificationExpiry",
    );
    if (!user || String(user.refreshToken) === "") {
      throw new ApiError(401, "Invalid access Token");
    }
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, "Invalid access Token");
  }
});
