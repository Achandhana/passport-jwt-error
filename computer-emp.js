const express = require('express');
const router = express.Router();
const Person = require('../model/computer');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const key = require('../setup/myurl');
const jwt = require('jsonwebtoken');
router.post('/register', (req, res) =>{
    Person.findOne({empID: req.body.empID})
        .then(person =>{
            if(person){
                return res.status(400).json({error:'person registered with the specified name'});
            }else{
                const newPerson = new Person({
                    name: req.body.name,
                    empID: req.body.empID,
                    email: req.body.email,
                    password: req.body.password
                });
                //encrypt password using bcryptjs
                bcrypt.genSalt(10, (err, salt) =>{
                    bcrypt.hash(newPerson.password, salt, (err, hash) =>{
                        if(err){
                            console.log(err);
                        }
                        newPerson.password = hash;
                        newPerson.save()
                            .then(person =>{
                                res.send(person);
                            })
                            .catch(err => console.log(err));
                    })
                })
            }
        })
        .catch(err => console.log(err));
});

router.post('/login', (req, res) =>{
    const email = req.body.email;
    const password = req.body.password;
    Person.findOne({email})
        .then(person =>{
            if(!person){
                return res.status(404).json({validation_error:'person not found with the specified email'});
            }
           else{
            bcrypt.compare(password, person.password)
            .then(isCorrect =>{
                if(isCorrect){
                    // res.json({login:'login successfull'});
                    const payload = {
                        id:person.id,
                        name:person.name,
                        email:person.email,
                        empID: person.empID
                    };
                    jwt.sign(
                        payload,
                        key.secret,
                        {expiresIn: 3600},
                        (err, token) =>{
                            res.redirect('/computer_emp');
                            // res.status(200).json({message:'done', token});
                            return token;
                          
                        }
                    )
                }else{
                    res.status(400).json({password_error:'password mismatch'});
                }
            })
            .catch(err => console.log(err));
           }
        })
        .catch(err => console.log(err));
});

router.get('/computer_emp',passport.authenticate('jwt', {session:false}), (req, res) =>{
    // console.log(req);
    res.send('authenticated');
});
module.exports = router;