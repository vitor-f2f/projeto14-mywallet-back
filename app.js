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

const transactionSchema = joi.object({
    value: joi.number().positive().required(),
    description: joi.string().min(1).required(),
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
            .findOne({ name: signupInfo.name });

        if (nameExists) {
            return res.status(409).send("Usuario ja existe");
        }

        const emailUsed = await db
            .collection("userlist")
            .findOne({ email: signupInfo.email });

        if (emailUsed) {
            return res.status(409).send("Email está em uso");
        }

        const password = await bcrypt.hash(signupInfo.password, 10);

        const signupObj = {
            name: signupInfo.name,
            email: signupInfo.email,
            password: password,
            balance: 0,
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
            const response = {
                name: user.name,
                token: token,
            };
            res.status(200).send(response);
        } else {
            return res.status(401).send("Senha incorreta");
        }
    } catch (error) {
        return res.status(500).send("Erro na tentativa de login");
    }
});

app.post("/transaction/:type", async (req, res) => {
    const { type } = req.params;
    const transactionInfo = req.body;

    const { error } = transactionSchema.validate(transactionInfo, {
        abortEarly: false,
    });
    if (error) {
        return res.status(422).send("Erro de validação da transação");
    }

    if (type !== "entrada" && type !== "saida") {
        return res.status(400).send("Tipo de transação inválido");
    }

    const authToken = req.headers.authorization;
    if (!authToken) {
        return res.status(401).send("Não foi enviado token de autorização");
    }

    try {
        const session = await db
            .collection("sessions")
            .findOne({ token: authToken });
        if (!session) {
            return res.status(401).send("Token de autorização inválido");
        }

        const userId = session.userId;
        const user = await db
            .collection("userlist")
            .findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).send("Usuario não foi encontrado");
        }

        let balance = user.balance;
        if (type === "entrada") {
            balance += transactionInfo.value;
        } else if (type === "saida") {
            balance -= transactionInfo.value;
        }

        const transactionObj = {
            userId: userId,
            type: type,
            value: transactionInfo.value,
            description: transactionInfo.description,
        };

        await db.collection("transactions").insertOne(transactionObj);

        await db
            .collection("userlist")
            .updateOne({ _id: userId }, { $set: { balance } });

        return res.sendStatus(200);
    } catch (error) {
        return res.status(500).send("Erro na tentativa de transação");
    }
});

app.get("/account", async (req, res) => {
    const authToken = req.headers.authorization;
    if (!authToken) {
        return res.status(401).send("Não foi enviado token de autorização");
    }

    try {
        const session = await db
            .collection("sessions")
            .findOne({ token: authToken });
        if (!session) {
            return res.status(401).send("Token de autorização inválido");
        }

        const userId = session.userId;
        const user = await db
            .collection("userlist")
            .findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).send("Usuário não foi encontrado");
        }

        const transactionsList = await db
            .collection("transactions")
            .find({ userId: userId })
            .project({ type: 1, value: 1, description: 1, _id: 0 })
            .toArray();

        const response = {
            balance: user.balance,
            transactions: transactionsList,
        };

        return res.status(200).json(response);
    } catch (error) {
        return res.status(500).send("Erro ao buscar transações");
    }
});

/* ------ port setup ------ */

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
