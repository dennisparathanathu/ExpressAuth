const { verifySignUp } = require("../middleware");
const controller = require("../controllers/auth.controller");
const { authJwt } = require("../middleware");

module.exports = function(app) {
  app.use(function(req, res, next) {
    res.header(
      "Access-Control-Allow-Headers",
      "x-access-token, Origin, Content-Type, Accept"
    );
    next();
  });

  app.post(
    "/api/auth/signup",
    [
      verifySignUp.checkDuplicateUsernameOrEmail,
      verifySignUp.checkRolesExisted
    ],
    controller.signup
  );

  app.post("/api/auth/signin", controller.signin);

  app.put(
    "/api/edituser/:id",
    [authJwt.verifyToken, authJwt.isAdmin],
    controller.updateuser
  );
  app.delete(
    "/api/deleteuser/:id",
    [authJwt.verifyToken, authJwt.isAdmin],
    controller.deleteuser
  );
  app.get(
    "/api/allusers",
    [authJwt.verifyToken],
    controller.Allusers
  );
  app.put(
    "/api/logout",
    [authJwt.logout]
  );

  
};

