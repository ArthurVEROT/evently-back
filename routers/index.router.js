const router = require(`express`).Router();

router.get(`/`, (req, res, next) => {
  try {
    res.status(200).json({
      message: `Welcome to Evently 😁`,
      apiGithubRepo: `https://github.com/ArthurVEROT/evently-api`,
    });
  } catch (err) {
    next(err);
  }
});

// You put the next routes here 👇
// example: router.use("/auth", authRoutes)
router.use("/auth", require("./auth.router"));
router.use(`/reset-password`, require(`./resetPassword.router`));

router.use("/events", require("./events.router"));
router.use("/events", require("./attendees.router"));
router.use("/messages", require("./messages.router"));

router.use(`/me`, require(`./currentUser.router`));

router.use("/users", require("./users.router"));

module.exports = router;
