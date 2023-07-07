import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import joi from "joi";
import dotenv from "dotenv";
import { stripHtml } from "string-strip-html";
import { v4 as uuid } from "uuid";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// conexão e criação do db
const client = new MongoClient(process.env.DATABASE_URL);

client.connect((error) => {
    if (error) {
        console.log(`Falha na conexão com MongoDB: ${error}`);
        process.exit(1);
    }

    console.log("Conectado a MongoDB");
});

let db = client.db();

/* ------ schemas ------ */

const signupSchema = joi.object({
    name: joi.string().min(1).required(),
    email: joi.string().email().required(),
    password: joi.string().min(1).required(),
});

const signinSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().min(1).required(),
});

/* ------ requests ------ */

app.post("/signup", async (req, res) => {
    let signupInfo = req.body;
    const { error } = signupSchema.validate(signupInfo, {
        abortEarly: false,
    });
    if (error) {
        return res.status(422).send("Erro de validação do usuario");
    }
    try {
        const nameExists = await db
            .collection("userlist")
            .findOne({ name: userlist.name });

        if (nameExists) {
            return res.status(409).send("Usuario ja existe");
        }

        const emailUsed = await db
            .collection("userlist")
            .findOne({ name: userlist.email });

        if (emailUsed) {
            return res.status(409).send("Email está em uso");
        }

        const password = await bcrypt.hash(signupInfo.password, 10);

        const signupObj = {
            name: signupInfo.name,
            email: signupInfo.email,
            password: password,
        };

        await db.collection("userlist").insertOne(signupObj);
        return res.sendStatus(201);
    } catch (error) {
        return res.status(500).send("Erro na tentativa de cadastro");
    }
});

app.post("/signin", async (req, res) => {
    let signinInfo = req.body;
    const { error } = signinSchema.validate(signinInfo, {
        abortEarly: false,
    });
    if (error) {
        return res.status(422).send("Erro de validação do usuario");
    }
    try {
        const user = await db.collection("userlist").findOne({
            email: signinInfo.email,
        });
        if (!user) {
            return res.status(404).send("Email não registrado");
        }

        const passwordCheck = await bcrypt.compare(
            signinInfo.password,
            user.password
        );

        if (passwordCheck) {
            const token = uuid();
            await db
                .collection("sessions")
                .insertOne({ userId: user._id, token });
            res.status(200).send(token);
        } else {
            return res.status(401).send("Senha incorreta");
        }
    } catch (error) {
        return res.status(500).send("Erro na tentativa de login");
    }
});

/* ------ port setup ------ */

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Usando porta ${PORT}`);
});
