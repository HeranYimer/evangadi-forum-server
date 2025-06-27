import pool from "../config/databaseConfig.js";
import bcrypt from "bcrypt";
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";

//Register
export async function register(req, res) {
  const { username, first_name, last_name, email, password } = req.body;

  //check if all fields are provided
  if (!email || !password || !first_name || !last_name || !username) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "please provide all required information!",
      error: "All Fields are Required",
    });
  }

  //Password length Check
  if (password.trim().length < 8) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "password must be at least 8 characters" });
  }

  try {
    //check if username or email already exists(row, field)
    const [user] = await pool.query(
      "SELECT username, user_id from users where username = ? or email =?",
      [username, email]
    );

    if (user.length > 0) {
      if (user[0].email === email) {
        return res
          .status(StatusCodes.CONFLICT)
          .json({ error: "An account with this email already exists" });
      }

      if (user[0].username === username) {
        return res
          .status(StatusCodes.CONFLICT)
          .json({ error: "This username is already taken" });
      }
    }

    //encrypt the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.execute(
      "INSERT INTO users (username, first_name, last_name, email, password) VALUES (?,?,?,?,?)",
      [username, first_name, last_name, email, hashedPassword]
    );

    return res.status(StatusCodes.CREATED).json({
      success: true,
      status: 201,
      msg: "user created",
    });
  } catch (error) {
    console.log(error.message);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      msg: "something went wrong, try again later!",
      error: "Registration Failed. Please Try Again",
    });
  }
}

//Login
export async function login(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "please enter all required fields",
      error: "Email and Password are Required",
      // error: "Email and password are required.",//**************************************************************BA */
    });
  }

  try {
    //Finding User using Email
    const [user] = await pool.execute(
      "SELECT username, user_id, password from users where email = ? ",
      [email]
    );

    if (user.length == 0) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        msg: "User not found",
        error: "Invalid Credentials",
        // error: "Invalid email or password.",//************************************************************************************************************BA
      });
    }
    //compare password
    const isMatch = await bcrypt.compare(password, user[0].password);
    if (!isMatch) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ msg: "invalid credential" });
    }

    //json webtoken
    const { username, user_id } = user[0];

    const token = jwt.sign({ username, user_id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.status(StatusCodes.OK).json({
      msg: "user login successful",
      success: true,
      user: {
        user_id: user[0].user_id,
        username: user[0].username,
      },
      token,
    });

    //  console.log(`User logged in: ${user.username} (ID: ${user.user_id})`)
    console.log(user);
  } catch (error) {
    console.log(error.message);

    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      sucess: false,
      msg: "something went wrong, try again later!",
      error: `Login Failed. Please Try again Later ${error.message}`,

      // console.error("Login error:", error); // Log full error internally
      // res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      //   error: "An unexpected error occurred. Please try again later.",//*********************************************BA */
    });
  }
}

//CheckUser
export async function checkUser(req, res) {
  // req.user comes from JWT middleware(user info from verified token)
  const userId = req.user.user_id;

  try {
    const [users] = await pool.execute(
      "SELECT user_id, username, first_name, last_name, email FROM users WHERE user_id = ?",
      [userId]
    );
    console.log(users[0]);

    if (users.length === 0) {
      console.warn(`User with ID ${userId} not found in DB`);
      return res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        status: 404,
        error: "User not found",
      });
    }

    res.status(StatusCodes.OK).json({
      success: true,
      status: 200,
      message: "User profile retrieved successfully",
      user: users[0],
    });
  } catch (error) {
    console.error("Get profile error:", error.message);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      status: 500,
      error: "Failed to get user profile",
    });
  }
}
