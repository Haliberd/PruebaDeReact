const express = require("express")
const users = express.Router()

const cors = require("cors")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")

const User = require("../models/User")

users.use(cors())


process.env.SECRET_KEY = 'secret'


//Permite registrar al usuario. Hasta el momento no se ha tomado en cuenta el apartado de roles.
users.post('/register', (req, res) => {
	const today = new Date()
	const userData = {
		first_name: req.body.first_name,
		last_name: req.body.last_name,
		email: req.body.email,
		password: req.body.password,
		created: today
	}

	User.findOne({
		where: {
			email: req.body.email
		}
	})
	.then(user =>{
		if(!user){
			const hash = bcrypt.hash(req.body.password, 10, (err, hash) => {
				userData.password = hash
				User.create(userData)
				.then(user => {
					res.json({status: user.email + ' registered'})
				})
				.catch(err => {
					res.send('error' + err)
				})
			})
		}else{
			res.json({error: "User already exist"})
		}
	})
	.catch(err => {
		res.send('error: ' + err)
	})
})

//Funcion que permite al usuario logear. Hasta el momento no he visto como hacer que el token expire.
users.post('/login', (req, res) => {
	User.findOne({
		where: {
			email: req.body.email
		}
	})
	.then(user => {
		if(user){
			if(bcrypt.compareSync(req.body.password, user.password)){
				let token = jwt.sign(user.dataValues, process.env.SECRET_KEY, {
					expiresIn: 60
				})
				res.send(token)
			}
			else{
				res.end()
			}
		}else{
			res.status(400).json({error: 'User does not exist'})
			res.end()
		}
	})
	.catch(err => {
		res.status(400).json({error: err})
	})
})

//Funcion para eliminar usuarios usando un correo, los borra de la tabla de users.
//Esta funcion será cambiada por una que funcione como update, para desactivar el usuario,
//mas que borrarlo.
users.post('/delete', (req, res) => {
	User.findOne({
		where: {
			email: req.body.email
		}
	})
	.then(user => {
		if(user){
			User.destroy({
				where: {
					email: req.body.email
				}
			})
			.then(user => {
				res.json({status: req.body.email + ' deleted'})
			})
			.catch(user => {
				res.json({error: "Can't delete user."})
			})
		}else{
			res.status(400).json({error: 'User does not exist'})
			res.end()
		}
	})
	.catch(err => {
		res.status(400).json({error: err})
	})
})

//Permite cambiar la contraseña de un usuario identificado por un correo.
//Es necesario el introducir la contraseña antigua y la nueva (obviamente).
users.post('/updatePassword', (req, res) => {
	User.findOne({
		where: {
			email: req.query.email
		}
	})
	.then(user => {
		if(user){
			if(bcrypt.compareSync(req.body.oldPassword, user.password)){
				const hash = bcrypt.hash(req.body.newPassword, 10, (err, hash) => {
					User.update(
						{password: hash},
						{where: { email: req.query.email } }
					)
					.then(result =>{
							res.json({status: req.query.email + ' updated'})
					})
					.catch(err =>{
							res.json({error: err})
					})
				})
			}
			else{

			}
		}	else{
			res.status(400).json({error: 'User' + req.query.email + 'does not exist'})
			res.end()
		}
	})
	.catch(err => {

	})
})

module.exports = users