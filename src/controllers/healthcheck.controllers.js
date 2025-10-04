import { ApiResponse } from "../utils/api_response.js";
import { asyncHandler } from "../utils/async_handler.js";

/* 
const healthCheck = async (req, res, next) => {
  try {
    res
    .status(200)
    .json(new ApiResponse(200, { message: "Server is running" }));
    } catch (error) {
    next(err);
    }
    };
    */
const healthCheck = asyncHandler(async (req, res, next) => {
  res.status(200).json(new ApiResponse(200, { message: "Server is running" }));
});

export { healthCheck };
