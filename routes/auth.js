const router = require("express").Router();
const User = require("../model/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { registerValidation, loginValidation } = require("../validation");

router.post("/register",async (req, res) => {
    //console.log("herer");
   // validate the user
    const { error } = registerValidation(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }
    const isEmailExist = await User.findOne({ email: req.body.email });
    if (isEmailExist) {
        return res.status(400).json({error:"Email already Exist"});
    }

    // hash the password
    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(req.body.password, salt);

    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password,
    });

    try {
        const savedUser = await user.save();
        res.json({ error: null, data: savedUser });
      } catch (error) {
        res.status(400).json({ error });
      }
});

router.post("/login", async (req, res) => {
    const { error } = loginValidation(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }
    //find the email    
    const user = await User.findOne({ email: req.body.email });
    // throw error when email is wrong
    if (!user) return res.status(400).json({ error: "Email is wrong" });

    // check for password correctness
    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword)
        return res.status(400).json({ error: "Password is wrong" });

        // create token
     const token = jwt.sign(
        // payload data
        { name: user.name,
            id: user._id,
        },
            process.env.TOKEN_SECRET
        );
        res.header("auth-token", token).json({
            error: null,
            data: {
              token,
            },
          });
    /*res.json({error: null, data: {message: "Login successful",},});*/
});    
    
module.exports = router;