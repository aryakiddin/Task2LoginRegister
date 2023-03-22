const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const User = require('./models/user')
const Event = require('./models/event')
require('dotenv').config()

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

mongoose.connect('mongodb://127.0.0.1:27017/users', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//schema definition for "register" request body
const registerSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

//schema definition for "login" request body
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

//schema definition for "updatePassword" request body
const updatePasswordSchema = Joi.object({
  id: Joi.string().required(),
  newPassword: Joi.string().required(),
});

////schema definition for "resetPassword" request body
const resetPasswordSchema = Joi.object({
  email: Joi.string().email().required(),
});

//declaring variables for jwt token creation/verify
const SECRET_KEY = 'my-secret-key'

const jwtOptions = {
    expiresIn:'1h'
  }
  
  

//API endpoint  to register a new user
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = await registerSchema.validateAsync(req.body);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).send({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, SECRET_KEY, jwtOptions);
    user.tokens.push({ token });
    await user.save();

    res.status(201).send({ message: 'User created successfully', token });
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});


//API endpoint to login the user

app.post('/login', async (req, res) => {
  try {
    const { email, password } = await loginSchema.validateAsync(req.body);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).send({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user._id }, SECRET_KEY, jwtOptions);
    user.tokens.push({ token });
    await user.save();

    res.status(200).send({ message: 'Login successful', token });
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});


//API endpoint to logout the user
app.post('/logout', async (req, res) => {
  try {
    const { token } = req.body;

    const user = await User.findOne({ 'tokens.token': token });
    if (!user) {
      return res.status(401).send({ message: 'Invalid token' });
    }

    user.tokens = user.tokens.filter(t => t.token !== token);
    await user.save();

    res.status(200).send({ message: 'Logout successful' });
  } catch (err) {
    res.status(400).send({ message: err.message });
}
});


//API endpoint to change password
app.post('/change-password', async (req, res) => {
    try {
    const { id, newPassword } = await updatePasswordSchema.validateAsync(req.body);
    const hashedPassword = await bcrypt.hash(newPassword, 10);

const user = await User.findById(id);
if (!user) {
  return res.status(404).send({ message: 'User not found' });
}

user.password = hashedPassword;
user.tokens = [];
await user.save();

res.status(200).send({ message: 'Password updated successfully' });
} catch (err) {
    res.status(400).send({ message: err.message });
    }
    });
    
app.post('/reset-password', async (req, res) => {
    try {
         const { email } = await resetPasswordSchema.validateAsync(req.body);
            const user = await User.findOne({ email });
        if (!user) {
             return res.status(404).send({ message: 'User not found' });}
        const token = uuidv4();
        user.tokens.push({ token });
        await user.save();

    //return token
        res.status(200).send({ message: 'Token generated successfully', token });
        } catch (err) {
        res.status(400).send({ message: err.message });
        }
 });

 //middleware definition that verifies the user's jwt
const authenticate = async (req, res, next) => {
    try {
      const token = req.header('Authorization').replace('Bearer', '');
      const decoded = jwt.verify(token, SECRET_KEY);
      const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });
  
      if (!user) {
        throw new Error('User not authenticated');
      }
  
      req.user = user;
      req.token = token;
      next();
    } catch (err) {
      res.status(401).send({ message: err.message });
    }
  };

  //api end point to create a new EVENT
app.post('/events', authenticate, async (req, res) => {
    try {
      const { title, description, date } = req.body;
  
      const event = new Event({
        title,
        description,
        date,
        createdBy: req.user._id
      });
  
      await event.save();
  
      res.status(201).send({ message: 'Event created successfully', event });
    } catch (err) {
      res.status(400).send({ message: err.message });
    }
  });



app.listen(port, () => {
    console.log(`Server running on port ${port}...`);
    });