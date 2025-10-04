import { Router } from "express";
import {
  registerUser,
  login,
  logoutUser,
  verifyEmail,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  getCurrentUser,
  changeCurrentPassword,
  resendEmailVerification,
} from "../controllers/auth.controllers.js";
import { validate } from "../middleware/validator.middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
} from "../validators/index.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser); //tested

router.route("/login").post(userLoginValidator(), validate, login); //tested

router.route("/verify-email/:verificationToken").get(verifyEmail); //tested

router.route("/refesh-token").post(refreshAccessToken); //tested

router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest); //tested

router
  .route("/reset-password/:resetToken")
  .post(userResetForgotPasswordValidator(), validate, resetForgotPassword); //tested

//secure routes
router.route("/logout").post(verifyJWT, logoutUser); //tested
router.route("/cuurent-user").post(verifyJWT, getCurrentUser); //tested
router
  .route("/change-password")
  .post(
    verifyJWT,
    userChangeCurrentPasswordValidator(),
    validate,
    changeCurrentPassword,
  ); //tested

router
  .route("/resend-email-verification")
  .post(verifyJWT, resendEmailVerification); //tested

export default router;
