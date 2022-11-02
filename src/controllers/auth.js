const { response } = require('express');
const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async (req, res = response) => {

    const { email, name, password } = req.body;

    try {
        // Verificar el email
        const usuario = await Usuario.findOne({email});

        if(usuario) {
            return res.status(400).json({
                ok: false,
                msg: 'El usuario ya existe con ese email'
            });
        }

        // Crear usuario con el modelo
        const dbUsuario = new Usuario(req.body);

        // Hashear la contraseña
        const salt = bcrypt.genSaltSync();
        dbUsuario.password = bcrypt.hashSync(password, salt);

        // Generar el JWT
        const token = await generarJWT(dbUsuario.id, name);

        // Crear usuario de DB
        await dbUsuario.save();

        //Generar respuesta exitosa
        return res.status(201).json({
            ok: true,
            uid: dbUsuario.id,
            name,
            email,
            token
        })
    } catch(error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Por favor comuníquese con el administrador'
        });

    }
};

const loginUsuario = async (req, res = response) => {

    const { email, password } = req.body;

    try {
        const dbUsuario = await Usuario.findOne({email});

        if(!dbUsuario) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }

        // Confirmar si el password hace match
        const validPassword = bcrypt.compareSync(password, dbUsuario.password);

        if(!validPassword) {
            return res.status(400).json({
                ok: false,
                msg: 'El password no es valido'
            });
        }

        // Generar el JWT
        const token = await generarJWT(dbUsuario.id, dbUsuario.name);

        // Respuesta del servicio
        return res.json({
            ok: true,
            uid: dbUsuario.id,
            name: dbUsuario.name,
            email,
            token
        });

    } catch(error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Por favor comuníquese con el administrador'
        });
    }
};

const revalidarToken = async (req, res) => {

    const { uid } = req;

    const dbUsuario = await Usuario.findById(uid);


    
    const token = await generarJWT(uid, dbUsuario.name);

    return res.json({
        ok: true,
        uid,
        name: dbUsuario.name,
        email: dbUsuario.email,
        token
    });
};

module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}