const express = require('express');
const router = express.Router();
const SingUpTemplatedb = require('../models/singupmodel');
const cors = require('cors')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

router.delete('/logout', (req, res)=> {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  res.sendStatus(204)
})


let refreshTokens = ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImRkQGRyLmpqIiwicGFzc3dvcmQiOiIkMmIkMTAkVUFveEx0b3E4c25XRzBWdVZDMGpILnRiTHlTeWMubE8yTXpscFo1cDFJR1RWTkhvcUpUQm0iLCJpYXQiOjE2MzQ4OTgwOTl9.hD6spSiXfqeKUzMgsAV58umyYySE9p6owBF3biWG_8E"]
router.post('/token', (req, res) => {
  const refreshToken = req.body.token
  if(refreshToken == null) return res.sendStatus(401);
  if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if(err) return res.sendStatus(403);
    const accessToken = jwt.sign({email:user.email, password:user.password}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
    res.json({accessToken,})
  })
})



function authenticationToken(req, res, next){
  const authHeader = req.headers['authorization'];
  const token = authHeader.split(' ')[0];
  if(token == null) return res.sendStatus(401);
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=>{
    if(err) return res.sendStatus(403)
    req.user = user;
    next()
  })
}

router.get('/post',authenticationToken, (req, res) =>{
  res.status(200).json({email:req.user});
})


router.post("/singup", cors(), async (request, response) => {
  SingUpTemplatedb.findOne({email: request.body.email}, async function (err, myUser) {
    if(myUser == null){
      const saltPassword = await bcrypt.genSalt(10);
      const securedPassword = await bcrypt.hash(request.body.password, saltPassword)
      request.body.password = securedPassword;
      try {
        const accessToken = jwt.sign({email:request.body.email, password:request.body.password}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
        const refreshToken = jwt.sign({email:request.body.email, password:request.body.password}, process.env.REFRESH_TOKEN_SECRET)
        response.json({accessToken, refreshToken});
        request.body.token = refreshToken;
        const user = new SingUpTemplatedb(request.body);
        await user.save();
      } catch (error) {
        response.status(500).send(error);
      }
    }else{
      response.status(500).send(err);
    }
  })
});


router.post("/login", cors(), async (request, response) => {
  SingUpTemplatedb.findOne({email: request.body.email}).exec(async function (err, myUser) {
      const ispassword = await bcrypt.compare(request.body.password, myUser.password)
      if(myUser != null && ispassword){
        try {
        const accessToken = jwt.sign({email:request.body.email, password:request.body.password}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
        response.json({accessToken,refreshToken:myUser.token});
        } catch (error) {
          response.status(500).send(error);
        }
      }else{
        response.status(500).send(err);
      }

  })
});


module.exports = router;
