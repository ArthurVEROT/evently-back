const router = require(`express`).Router(),
  User = require(`../models/User.model`),
  bcrypt = require(`bcryptjs`),
  jwt = require(`jsonwebtoken`),
  nodemailer = require(`nodemailer`)

const {
    handleNotExist,
    isValidPassword,
    handleInvalidPassword,
    handleImagePath,
  } = require(`../utils/helpers.function`)
  
const uploader = require("../config/cloudinary.config");

const saltRounds = 10;


//
// Sign Up router
//
// uploader.single("keyName of the input")
router.post("/signup", uploader.single("file"), async (req, res, next) => {
  try {
    const imageUrl = handleImagePath(req.file, "file");
    const { username, email, password } = req.body;

    // Checking if email is an empty string
    if (!email) {
      res.status(400).json({ message: "Email cannot be empty" });
      return;
    }

    //Checking if email already exist
    const emailFound = await User.findOne({ email });
    if (emailFound) {
      res.status(400).json({ message: `Email already exists` });
      return;
    }

    // Check if password is valid
    if (!isValidPassword(password)) {
      handleInvalidPassword(res, next);
      return;
    }

    // Hashing password
    const salt = await bcrypt.genSalt(saltRounds),
      hashedPassword = await bcrypt.hash(password, salt);

    // Create user in DB
    const createdUser = await User.create({
      username,
      name: username,
      email,
      password: hashedPassword,
      imageUrl,
    });

    // // Verify token
    // const verifToken = jwt.sign(
    //   { userId: createdUser.id },
    //   process.env.TOKEN_SECRET,
    //   {
    //     algorithm: `HS256`,
    //     expiresIn: `15m`,
    //   }
    // );

    // // Send email
    // const transporter = nodemailer.createTransport({
    //   service: "Gmail",
    //   auth: {
    //     user: process.env.EMAIL_USERNAME,
    //     pass: process.env.APP_PASSWORD,
    //   },
    // });
    // // use .env for the from field
    // const emailResMsg = await transporter.sendMail({
    //   from: `Evently <${process.env.EMAIL_USERNAME}>`,
    //   to: createdUser.email,
    //   subject: "Email Verification",
    //   text: `${process.env.BASE_URL}/verify?email=${createdUser.email}&token=${verifToken}`,
    // });

    // console.log(emailResMsg);

    res.sendStatus(201);
  } catch (err) {
    next(err);
  }
});

//
// Login router
//
router.post(`/login`, async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const credential = username ? { username } : { email };

    // Check email or username
    const foundUser = await User.findOne(credential);
    // Check password
    const isPasswordMatched = await bcrypt.compare(
      password,
      foundUser.password
    );

    if (!foundUser || !isPasswordMatched) {
      res.status(400).json({ message: `email or password incorrect` });
      return;
    }

    // Check if user is verified
    if (!foundUser.isVerified) {
      res.status(401).json({
        errors: {
          verification: `account not verified`,
        },
      });
      return;
    }

    //Create auth token
    const authToken = jwt.sign(
      { userId: foundUser.id },
      process.env.TOKEN_SECRET,
      {
        algorithm: `HS256`,
        expiresIn: `7d`,
      }
    );

    res.status(200).json({ isLoggedIn: true, authToken });
  } catch (err) {
    next(err);
  }
});

//
// Verify router
//
router.get("/verify", async (req, res, next) => {
  // Get the bearer token from the header
  const { authorization } = req.headers;
  // extract the jwt
  const token = authorization.replace("Bearer ", "");

  try {
    // verify the web token
    const playload = jwt.verify(token, process.env.TOKEN_SECRET);
    // send the user the payload
    res.json({ token, playload });

    // if error, catch it and say token is invalid
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
});

// //
// // Verify email
// //
// router.get(`/verify-email`, async (req, res, next) => {
//   try {
//     const verifToken = req.query.token;

//     if (!verifToken) {
//       res.status(400).json({
//         errors: {
//           verifToken: `verification token missing`,
//         },
//       });
//       return;
//     }

//     const { userId } = jwt.verify(verifToken, process.env.TOKEN_SECRET);

//     const foundUser = await User.findByIdAndUpdate(
//       userId,
//       { isVerified: true },
//       { new: true, select: { password: 0, __v: 0 } }
//     );

//     if (!foundUser) {
//       handleNotExist(`user`, userId, res);
//       return;
//     }

//     // const transporter = nodemailer.createTransport({
//     //   service: "Gmail",
//     //   auth: {
//     //     user: process.env.EMAIL_USERNAME,
//     //     pass: process.env.APP_PASSWORD,
//     //   },
//     // });

//     // // use .env for the from field
//     // const emailResMsg = await transporter.sendMail({
//     //   from: `Evently <${process.env.EMAIL_USERNAME}>`,
//     //   to: foundUser.email,
//     //   subject: "Email Verification",
//     //   text: `You are now a verified user!`,
//     // });

//     // console.log(emailResMsg);

//     res.status(200).json(foundUser);
//   } catch (err) {
//     err.unverifiedUser = req.query.email;
//     next(err);
//   }
// });


module.exports = router;
