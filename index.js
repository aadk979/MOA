const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const CryptoJS = require("crypto-js");
const admin = require("firebase-admin");
const serviceAccount = require("./project-moa-b740c-firebase-adminsdk-sej04-e2475f90d9.json");
const validator = require("validator");
const { scryptSync, randomBytes, timingSafeEqual } = require("crypto");
const zxcvbn = require("zxcvbn");
const rateLimit = require("express-rate-limit");
const requestIp = require("request-ip");
const jwt = require("jsonwebtoken");
const SERVER = { key: "C86C82F7CA6DEB140554D03BF65FB18C" };
const JWT_AUTH_SECRET = "secret"; // temporary secret to be replaced with env variable

const app = express();
const port = 6969;

const limiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    message:
        "<h1 style='text-align:center; color:red; font-family:sans-serif;'>Too many requests from this IP, please try again after 5 minutes</h1>",
});

app.use(limiter);
app.use(requestIp.mw());

app.get("/", (req, res) => {
    res.send(
        '<h1 style="text-align:center; color:red; font-family:sans-serif;">This is the MOA backend endpoint.</h1>',
    );
    res.end();
});

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

const transactionID_global = [];

async function wipeDataBase() {
    const firestore = admin.firestore();
    const collections = await firestore.listCollections();
    return Promise.all(
        collections.map(async (collection) => {
            const querySnapshot = await collection.get();
            const deleteBatch = firestore.batch();
            querySnapshot.docs.forEach((doc) => {
                deleteBatch.delete(doc.ref);
            });
            await deleteBatch.commit();
        }),
    );
}

async function checkPasswordStrength(password) {
    const result = zxcvbn(password);
    if (result.score >= 3) {
        return "strong";
    } else {
        return "fail";
    }
}

async function generateJWT(payload, secretKey, options) {
    return jwt.sign(payload, secretKey, options);
}

async function verifyJWT(token, secretKey) {
    return new Promise((resolve, reject) => {
        try {
            jwt.verify(token, secretKey, (err, decoded) => {
                if (err) {
                    reject(false);
                } else {
                    resolve(decoded);
                }
            });
        } catch (e) {
            console.error(e);
            reject(false);
        }
    });
}

function generateRandomNumber(min, max) {
    if (typeof min !== "number" || typeof max !== "number" || min >= max) {
        throw new Error(
            "Invalid parameters: min must be less than max and both must be numbers.",
        );
    }
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    const yahooRegex = /^[a-zA-Z0-9._%+-]+@yahoo\.com$/;
    if (!emailRegex.test(email)) {
        return "Invalid email format";
    }
    if (gmailRegex.test(email)) {
        return "Valid email";
    }
    if (yahooRegex.test(email)) {
        return "Valid email";
    }
    return "Valid email";
}

async function generateUID(value) {
    let length = value || 200;
    let characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let uid = "";
    for (let i = 0; i < length; i++) {
        let randomIndex = Math.floor(Math.random() * characters.length);
        uid += characters.charAt(randomIndex);
    }
    return uid;
}

async function sanitizeInput(input) {
    if (typeof input !== "string") {
        throw new Error("Input must be a string");
    }
    let sanitizedInput = validator.trim(input);
    sanitizedInput = validator.escape(sanitizedInput);
    return sanitizedInput;
}

function generateKey() {
    const keyLength = 256 / 4;
    let key = "";
    const characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (let i = 0; i < keyLength; i++) {
        key += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return key;
}

function encrypt(Data, key) {
    return new Promise((resolve, reject) => {
        try {
            const encrypted = CryptoJS.AES.encrypt(
                Data,
                CryptoJS.enc.Hex.parse(key),
                { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 },
            );
            resolve(encrypted.toString());
        } catch (e) {
            console.error(e);
            reject(null);
        }
    });
}

function decrypt(encryptedData, key) {
    return new Promise((resolve, reject) => {
        try {
            const decrypted = CryptoJS.AES.decrypt(
                encryptedData,
                CryptoJS.enc.Hex.parse(key),
                { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 },
            );
            const data = decrypted.toString(CryptoJS.enc.Utf8);
            resolve(data);
        } catch (e) {
            console.error(e);
            reject(null);
        }
    });
}

async function storeData(data, collection, doc) {
    return new Promise(async (resolve, reject) => {
        const Data = await encrypt(JSON.stringify(data) , SERVER.key);
        admin
            .firestore()
            .collection(collection)
            .doc(doc)
            .set({data: Data})
            .then(() => {
                resolve(200);
            })
            .catch((e) => {
                reject(new Error(e));
            });
    });
}

async function fetchData(collection, doc) {
    return new Promise(async (resolve, reject) => {
        try {
            const data = await admin
                .firestore()
                .collection(collection)
                .doc(doc)
                .get();
            if (data.exists) {
                const toReturn = data.data();
                const decryptedToReturn = await decrypt(toReturn.data , SERVER.key);
                resolve(JSON.parse(decryptedToReturn));
            } else {
                resolve(null);
            }
        } catch (e) {
            reject(new Error(e));
        }
    });
}

function generateTransactionID(length = 200) {
    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?";
    let transactionID = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        transactionID += characters[randomIndex];
    }
    return transactionID;
}

async function hashPassword(password) {
    const salt = randomBytes(32).toString("hex");
    const hashedPassword = scryptSync(password, salt, 256).toString("hex");
    const toReturnPassword = `${salt}:${hashedPassword}`;
    return toReturnPassword;
}

async function hashedPasswordVerify(password, password_to_verify) {
    const [salt, key] = password.split(":");
    const hashedBuffer = scryptSync(password_to_verify, salt, 256);
    const keyBuffer = Buffer.from(key, "hex");
    const match = timingSafeEqual(hashedBuffer, keyBuffer);
    return match;
}

function calculateAge(birthDateArray) {
    let [day, month, year] = birthDateArray;
    let birthDate = new Date(year, month - 1, day);
    let today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    let monthDifference = today.getMonth() - birthDate.getMonth();
    let dayDifference = today.getDate() - birthDate.getDate();
    if (monthDifference < 0 || (monthDifference === 0 && dayDifference < 0)) {
        age--;
    }
    return age;
}

async function validateServiceConfig(serviceConfig, domain, test) {
    // servicConfig = {service_id , serviceToken , temporaryToken }
    if (test) {
        return true;
    }

    if (!domain) {
        console.log("domain fail");
        return false;
    }

    const {
        service_id,
        serviceToken,
        service_name,
        serviceExplicityLevel,
        minorEnforcment,
        serviceType,
        lengths,
        temporaryToken,
    } = serviceConfig;

    const service = await fetchData("services", service_id);

    //service = { id: service_id , token: service_token , authorisedDomains: authorisedDomains , serviceType: serviceType , key: service_key , name: service_name};

    if (service === null) {
        console.log("service fail");
        return false;
    }

    if (service === "error") {
        return false;
    }

    if (service.id.length !== lengths[0]) {
        return false;
    }

    if (service.token.length !== lengths[1]) {
        return false;
    }

    if (service.id !== service_id) {
        console.log("service id fail");
        return false;
    }

    if (service.token !== serviceToken) {
        console.log("service token fail");
        console.log(service.token === serviceToken);
        return false;
    }

    const authorisedDomains = service.authorisedDomains;
    const isDomainAuthorised = authorisedDomains.includes(domain);

    if (!isDomainAuthorised) {
        console.log("domain fail");
        let previousUnauthorisedRequests = await fetchData(
            "services",
            `${service_id}-UNAUTHORISED-REQUESTS`,
        );
        if (
            previousUnauthorisedRequests === null ||
            !Array.isArray(previousUnauthorisedRequests.domains)
        ) {
            previousUnauthorisedRequests = { domains: [] };
        }
        previousUnauthorisedRequests.domains.push({ from: domain });
        await storeData(
            { domains: previousUnauthorisedRequests.domains },
            "services",
            `${service_id}-UNAUTHORISED-REQUESTS`,
        );
        return "Domain not allowed";
    }

    const tokenVerify = await decrypt(temporaryToken, SERVER.key);

    if (tokenVerify === null) {
        return false;
    }

    const temporaryTokenVerify = await decrypt(tokenVerify, service.key);

    if (temporaryTokenVerify === null) {
        return false;
    } else {
        return true;
    }
}

app.use(
    cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }),
);

app.use(bodyParser.json());

app.post("/api/transactionID_creation", (req, res) => {
    const userIp = req.clientIp;
    const key = generateKey();
    const transactionID = generateTransactionID();
    transactionID_global[transactionID] = { key: key, ip: userIp };
    res.status(200).json({
        transactionID: transactionID,
        key: key,
        window: "15 MIN",
    });
    res.end();
    setTimeout(
        () => {
            transactionID_global[transactionID] = "expired";
        },
        15 * 60 * 1000,
    );
});

app.post("/api/signup_user", async (req, res) => {
    try {
        const { email, password, transactionID } = req.body;
        const userIp = req.clientIp;
        const transactionData = transactionID_global[transactionID];

        if (!transactionData) {
            res.status(404).json({ error: "Invalid transaction ID" });
            res.end();
            return;
        }

        if (transactionData === "expired") {
            res.status(404).json({ error: "Transaction ID expired" });
            res.end();
            return;
        }

        if (transactionData.ip !== userIp) {
            res.status(401).json({ error: "Unauthorized" });
            res.end();
            return;
        }

        const decryptedPassword = await decrypt(password, transactionData.key);
        const decrypEmail = await decrypt(email, transactionData.key);

        const sanitisedEmail = await sanitizeInput(decrypEmail);
        const sanitisedPassword = await sanitizeInput(decryptedPassword);
        const isEmailValid = await validateEmail(sanitisedEmail);
        const passwordStrong = await checkPasswordStrength(sanitisedPassword);
        const userExist = await fetchData(sanitisedEmail, "USER-UID");

        if (userExist !== null) {
            res.status(409).json({ error: "User already exists" });
            res.end();
            return;
        }

        if (isEmailValid !== "Valid email") {
            res.status(400).json({ error: "Invalid email format" });
            res.end();
            return;
        }

        if (passwordStrong !== "strong") {
            res.status(400).json({ error: "Password is weak" });
            res.end();
            return;
        }

        const userUID = await generateUID();
        const userKey = generateKey();
        const hashedPassword = await hashPassword(sanitisedPassword);

        storeData({ uid: userUID }, sanitisedEmail, "USER-UID")
            .then((x) => {
                if (x === 200) {
                    storeData(
                        {
                            uid: userUID,
                            key: userKey,
                            email: sanitisedEmail,
                            password: hashedPassword,
                            ip: userIp,
                        },
                        userUID,
                        "CREDENTIALS",
                    )
                        .then((y) => {
                            if (y === 200) {
                                console.log("user signed up succssfully");
                                res.status(200).json({
                                    message: "User registered successfully",
                                });
                                res.end();
                                return;
                            } else {
                                res.status(500).json({
                                    error: "Internal server error",
                                });
                                res.end();
                                return;
                            }
                        })
                        .catch((e) => {
                            res.status(500).json({ error: "Internal server error" });
                            res.end();
                            console.error(e);
                        });
                } else {
                    res.status(500).json({ error: "Internal server error" });
                    res.end();
                    return;
                }
            })
            .catch((e) => {
                res.status(500).json({ error: "Internal server error" });
                res.end();
                console.error(e);
            });
    } catch (e) {
        res.status(500).json({ error: "Internal server error" });
        res.end();
        console.error(e)
    }
});

app.post("/api/sign_in_user", async (req, res) => {
    try {
        const { email, password, serviceConfig, transactionID } = req.body;
        const userIp = req.clientIp;
        console.log(userIp);
        const transactionData = transactionID_global[transactionID];
        const domain = req.get("referer");
        const isServiceConfigValid = await validateServiceConfig(
            serviceConfig,
            domain,
            false,
        );

        if (!transactionData) {
            res.status(404).json({ error: "Invalid transaction ID" });
            res.end();
            return;
        }

        if (transactionData.ip !== userIp) {
            res.status(401).json({
                error: "Unauthorized",
                context: "IP mismatch",
            });
            res.end();
            return;
        }

        if (!serviceConfig) {
            res.status(401).json({
                error: "Unauthorized",
                context: "Service config not provided",
            });
            res.end();
            return;
        }

        if (isServiceConfigValid === "Domain not allowed") {
            res.status(401).json({
                error: "Unauthorized",
                context: "Domain not allowed",
            });
            res.end();
            return;
        }

        if (!isServiceConfigValid) {
            res.status(401).json({
                error: "Unauthorized",
                context: "Invalid service config",
            });
            res.end();
            return;
        }

        const service = await fetchData("services", serviceConfig.service_id);
        const decryptedPassword = await decrypt(password, transactionData.key);
        const decryptedEmail = await decrypt(email, transactionData.key);
        const sanitizedEmail = await sanitizeInput(decryptedEmail);
        const sanitizedPassword = await sanitizeInput(decryptedPassword);

        const userExist = await fetchData(sanitizedEmail, "USER-UID");

        if (!userExist) {
            res.status(404).json({ error: "No such user exists" });
            res.end();
            return;
        }

        const uid = userExist.uid;
        const user = await fetchData(uid, "CREDENTIALS");

        if (user.email !== sanitizedEmail) {
            console.log(sanitizedEmail);
            console.log(user.email);
            res.status(401).json({
                error: "Unautorized",
                context: "Email mismatch",
            });
            res.end();
            return;
        }

        if (user.uid !== uid) {
            res.status(401).json({
                error: "Unautorized",
                context: "UID mismatch",
            });
            res.end();
            return;
        }

        const hashedPassword = user.password;
        const authVerification = await hashedPasswordVerify(
            hashedPassword,
            sanitizedPassword,
        );

        if (authVerification) {
            const explicity = service.serviceExplicityLevel;
            const minorEnforcment = service.minorEnforcment;

            const user_data = await fetchData(user.uid, "USER-DATA");

            if (user_data === null) {
                res.status(400).json({
                    error: "User found but User has not fully set up their account",
                });
                res.end();
                return;
            } else {
                const userBirthday = user_data.Birthday || user_data.birthday;
                console.log(user_data);
                const userAge = calculateAge(userBirthday);

                if (explicity === "ADULT" && userAge < 18) {
                    res.status(401).json({
                        error: "Authentication was succesful but user is under 18 and service explicity level is ADULT",
                    });
                    res.end();
                    return;
                }

                if (explicity === "MATURE" && userAge < 18) {
                    res.status(401).json({
                        error: "Authentication was succesful but user is under 18 and service explicity level is MATURE",
                    });
                    res.end();
                    return;
                }

                if (
                    explicity === "SAFE" &&
                    minorEnforcment === "STRICT" &&
                    userAge < 18
                ) {
                    res.status(401).json({
                        error: "Authentication was succesful but user is under 18 , service explicity level is SAFE but minor enforcment is STRICT",
                    });
                    res.end();
                    return;
                }

                let userSignedServices = await fetchData(
                    uid,
                    "SIGNED-SERVICES",
                );
                let firstLogin = null;

                if (
                    userSignedServices === null ||
                    !Array.isArray(userSignedServices.userSignedServices)
                ) {
                    userSignedServices = [serviceConfig.service_id];
                    const save = await storeData(
                        { userSignedServices: userSignedServices },
                        uid,
                        "SIGNED-SERVICES",
                    );
                    if (save === 200) {
                        firstLogin = true;
                    }
                } else {
                    if (
                        userSignedServices.userSignedServices.includes(
                            serviceConfig.service_id,
                        )
                    ) {
                        firstLogin = false;
                    } else {
                        userSignedServices.userSignedServices.push(
                            serviceConfig.service_id,
                        );
                        const save = await storeData(
                            {
                                userSignedServices:
                                    userSignedServices.userSignedServices,
                            },
                            uid,
                            "SIGNED-SERVICES",
                        );
                        if (save === 200) {
                            firstLogin = true;
                        }
                    }
                }

                const token = await generateJWT(
                    { email: sanitizedEmail, uid: uid, ip: userIp },
                    JWT_AUTH_SECRET,
                    null,
                );
                const encryptedToken = await encrypt(
                    token,
                    transactionData.key,
                );
                res.status(200).json({
                    token: encryptedToken,
                    secured: true,
                    id: transactionID,
                    firstTime: firstLogin,
                });
                res.end();
                return;
            }
        } else {
            res.status(400).json({ error: "Invalid credentials" });
            res.end();
            return;
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Internal server error", error: e });
        res.end();
    }
});

app.post("/developer/api/create-service", async (req, res) => {
    try {
        const {
            service_name,
            authorisedDomains,
            serviceType,
            bearer,
            serviceExplicityLevel,
            minorEnforcment,
        } = req.body;
        const bearerValid = { uid: "dddd" }; //await verifyJWT(bearer , JWT_AUTH_SECRET);

        if (!bearerValid) {
            res.status(401).json({ error: "Unauthorized" });
            res.end();
            return;
        }

        const service_id_length = generateRandomNumber(1000, 1400);
        const service_token_length = generateRandomNumber(1000, 1400);

        const service_id = await generateUID(service_id_length);
        const service_token = await generateUID(service_token_length);
        const service_key = generateKey();

        const serviceConfig = {
            service_id: service_id,
            serviceToken: service_token,
            service_name: service_name,
            serviceExplicityLevel: serviceExplicityLevel,
            minorEnforcment: minorEnforcment,
            serviceType: serviceType,
            lengths: [service_id_length, service_token_length],
        };

        const service = {
            id: service_id,
            token: service_token,
            authorisedDomains: authorisedDomains,
            serviceType: serviceType,
            key: service_key,
            name: service_name,
            serviceExplicityLevel: serviceExplicityLevel,
            minorEnforcment: minorEnforcment,
            lengths: [service_id_length, service_token_length],
            user: bearerValid,
        };

        const system = await storeData(service, "services", service_id);

        const userLinkage = await storeData(
            {
                service_name: service_name,
                service_id: service_id,
                generatedOn: new Date(),
            },
            bearerValid.uid,
            "GENERATED-SERVICES",
        );

        res.status(200).json({
            message: "Service created successfully",
            serviceConfig: serviceConfig,
            system: [system, userLinkage],
        });
        res.end();
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Internal server error" });
        res.end();
    }
});

app.post("/api/generate-temporary-token", async (req, res) => {
    try {
        res.status(500).json({ message: "Endpoint disabled" });
        res.end();
        return;
        const { service_id } = req.body;
        const service = await fetchData("services", service_id);
        const temporaryToken = await generateUID(
            generateRandomNumber(200, 500),
        );
        const encryptedTemporaryToken = await encrypt(
            temporaryToken,
            service.key,
        );
        const encryptedTemporaryToken_second_round = await encrypt(
            encryptedTemporaryToken,
            SERVER.key,
        );
        res.status(200).json({
            temporaryToken: encryptedTemporaryToken_second_round,
        });
        res.end();
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Internal server error" });
        res.end();
    }
});

app.post("/api/set-up-account", async (req, res) => {
    try {
        const {
            Name,
            Email,
            Birthday,
            Age,
            Gender,
            PhoneNumber,
            Parent,
            MaritalStatus,
            CountryOfResidence,
            Nationality,
            Occupation,
            ProfilePhoto,
            transactionID,
        } = req.body;

        const userIp = req.clientIp;
        const transactionData = transactionID_global[transactionID];

        if (!transactionData) {
            res.status(404).json({ error: "Invalid transaction ID" });
            res.end();
            return;
        }

        if (transactionData === "expired") {
            res.status(404).json({ error: "Transaction ID expired" });
            res.end();
            return;
        }

        if (transactionData.ip !== userIp) {
            res.status(401).json({ error: "Unauthorized" });
            res.end();
            return;
        }
        
        const decrytedEmail = await decrypt(Email, transactionData.key);

        const user = await fetchData(decrytedEmail , 'USER-UID');

        console.log(user);

        if (!user){
            res.status(400).json({ error: true , context: 'User not found' });
            res.end();
            return;
        }

        const decryptedName = await decrypt(Name, transactionData.key);
        const decryptedGender = await decrypt(Gender, transactionData.key);
        const decryptedPhoneNumber = await decrypt(
            PhoneNumber,
            transactionData.key,
        );
        const decryptedMariatalStatus = await decrypt(
            MaritalStatus,
            transactionData.key,
        );
        const decrpytedOccupation = await decrypt(
            Occupation,
            transactionData.key,
        );
        const decryptedCountryOfResidence = await decrypt(
            CountryOfResidence,
            transactionData.key,
        );
        const decryptedNationality = await decrypt(
            Nationality,
            transactionData.key,
        );

        const user_data = {
            Name: decryptedName,
            Email: decrytedEmail,
            Gender: decryptedGender,
            Phone: decryptedPhoneNumber,
            Birthday: Birthday,
            Age: Age,
            Parent: Parent,
            MaritalStatus: decryptedMariatalStatus,
            Occupation: decrpytedOccupation,
            CountryOfResidence: decryptedCountryOfResidence,
            Nationality: decryptedNationality,
            ProfilePhoto: ProfilePhoto,
        };

        const user_data_exist = await fetchData(user.uid, "USER-DATA");

        if (user_data_exist) {
            res.status(400).json({
                error: "User data already exists , visit account update page",
            });
            res.end();
            return;
        }

        const save = await storeData(user_data, user.uid, "USER-DATA");

        if (save === 200) {
            res.status(200).json({ message: "Account set up successfully" });
            res.end();
            return;
        } else {
            res.status(500).json({ error: "Internal server error" });
            res.end();
            return;
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Internal server error" });
        res.end();
    }
});

app.post('/api/setup-passkey' , async (req , res) =>{
    try{
        
    }
    catch(e){
        res.status(500).json({error : "Internal server error"})
        res.end();
        console.error(e);
    }
})

app.listen(port, () => {
    console.log(`System up and running on port : ${port}`);
});
