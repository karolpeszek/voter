const environment = process.argv[2];
if (environment != '--test' && environment != '--prod') {
    console.log('No mode specified');
    process.exit(1);
}


const secrets = require(__dirname + "/secrets.json");
const config = require(__dirname + "/config.json");


const fastify = require('fastify')({ logger: environment == '--test' })
const mariadb = require('mariadb');
const getUuid = require('uuid-by-string');
const crypto = require('crypto');
const path = require('path')
const fs = require('fs');
const { renderHTML } = require("./render");
const puppeteer = require('puppeteer');



let conn = null;
let sessions = null;

fastify.register(require('@fastify/cookie'), {
    secret: secrets.sessionKey,
    hook: 'onRequest',
    parseOptions: {}
})
fastify.register(require('@fastify/cors'), config.cors);

const start = async () => {
    try {
        conn = await mariadb.createConnection(config.sql);
        await conn.query('USE ' + config.sql.database);
        await conn.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
        sessions = JSON.parse((await conn.query('SELECT value FROM sessions WHERE id=\'sessions\''))[0].value);
        fastify.log.info('Starting server on port', config.port);
        await fastify.listen({ port: config.port })

    } catch (err) {
        console.log(err);
        process.exit(1);
    }
}


// LOGIN AND LOGOUT
fastify.post('/api/admin/login', async (req, res) => {
    try {
        fastify.log.info('Starting admin login procedure');
        let parsedUserData = req.body;

        if (!parsedUserData ||
            !parsedUserData.username ||
            !parsedUserData.password ||
            typeof (parsedUserData.username) !== 'string' ||
            typeof (parsedUserData.password) !== 'string'

        ) throw 'MISSING_FIELDS';
        //search for the user in the database
        let userSearchResult = await conn.query('SELECT * FROM admins WHERE name=?', [parsedUserData.username]);


        if (userSearchResult.length != 1) throw 'USER_DOES_NOT_EXIST';

        let user = userSearchResult[0];

        let [salt, hash] = user.hash.split(':');
        //compute hash from the password that was sent by the user
        let userSentHash = generateHash(parsedUserData.password, salt);

        //check if hashes match
        let match = crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(userSentHash));
        fastify.log.info('Admin hash matched with password: ' + match);

        if (!match) throw 'WRONG_PASSWORD';

        //user authenticated, now issue a token
        let nonce = crypto.randomBytes(64).toString('base64');
        while (sessions[user.uuid][nonce]) nonce = crypto.randomBytes(64).toString('base64');


        let tokenObject = {
            nonce: nonce,
            username: user.name,
            email: user.email,
            uuid: user.uuid,
            admin: true
        }

        sessions[user.uuid][tokenObject.nonce] = tokenObject;
        saveSessions();
        //sign the token and send it to the user
        let token = res.signCookie(JSON.stringify(tokenObject));
        fastify.log.info('Issuing cookie to user', token);

        res.setCookie('token', token, { path: '/', secure: true, sameSite: environment == '--test' ? 'strict' : 'none', expires: Date.now() + config.cookieMaxAge });
        fastify.log.info('Admin login procedure succesfull');
        res.code(200).send(tokenObject);
    } catch (exception) {
        fastify.log.error('Admin login procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_DOES_NOT_EXIST':
                res.code(404);
                break;
            case 'MISSING_FIELDS':
                res.code(400);
                break;
            case 'WRONG_PASSWORD':
                res.code(403);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.post('/api/admin/logout', (req, res) => {
    try {
        try {

            let userObject = verifyToken(req.cookies.token);
            if (userObject)
                delete (sessions[userObject.uuid][userObject.nonce]);
            saveSessions();
        } catch (exception) {
            fastify.log.error('Error deleting cookie from sessions');
        }

        fastify.log.info('Logging out an admin.');
        res.clearCookie('token').code(200).send();
        fastify.log.info('Logging out an admin succefull');
    } catch (exception) {
        res.code(500).send({ error: exception });
    }
})
fastify.post('/api/admin/logoutall', (req, res) => {
    try {

        let userObject = verifyToken(req.cookies.token);
        if (!userObject || userObject == 'TEST_ONLY') throw 'USER_NOT_AUTHENTICATED';
        sessions[userObject.uuid] = {};
        saveSessions();


        fastify.log.info('Logging out an adminall.');
        res.clearCookie('token').code(200).send();
        fastify.log.info('Logging out an admin succefull');
    } catch (exception) {

        res.code(exception == 'USER_NOT_AUTHENTICATED' ? 401 : 500).send({ error: exception });
    }
})
fastify.post('/api/admin/logoutallall', (req, res) => {
    try {

        let userObject = verifyToken(req.cookies.token);
        if (!userObject || userObject == 'TEST_ONLY') throw 'USER_NOT_AUTHENTICATED';
        for (const uuid in sessions) sessions[uuid] = {};
        saveSessions();


        fastify.log.info('Logging out an adminallall.');
        res.clearCookie('token').code(200).send();
        fastify.log.info('Logging out an admin succefull');
    } catch (exception) {

        res.code(exception == 'USER_NOT_AUTHENTICATED' ? 401 : 500).send({ error: exception });
    }
})
fastify.get('/api/admin/currentuser', async (req, res) => {
    try {
        fastify.log.info('Starting current user procedure.');
        let token = req.cookies.token;
        if (!token) throw 'NO_COOKIE';

        let signedCorrectly = fastify.unsignCookie(token).valid;
        if (!signedCorrectly) throw 'INVALID_SIGNATURE';

        let cookieData = JSON.parse(fastify.unsignCookie(token).value);
        let userResponse = await conn.query('SELECT * FROM admins WHERE uuid=?', cookieData.uuid);
        if (userResponse.length == 0) throw 'USER_NOT_AUTHENTICATED';

        if (!sessions[cookieData.uuid] || !sessions[cookieData.uuid][cookieData.nonce]) throw 'COOKIE_EXPIRED';

        fastify.log.info('Current user procedure succesfull.');
        res.code(200).send(cookieData);
    } catch (exception) {
        fastify.log.error('Current user procedure failed with exception ' + exception);
        switch (exception) {
            case 'NO_COOKIE': case 'USER_NOT_AUTHENTICATED':
                res.code(401).send({ error: 'USER_NOT_AUTHENTICATED' });
                break;
            case 'INVALID_SIGNATURE':
                res.setCookie('token', 'INVALID_SIGNATURE_DELETING_COOKIE', { path: '/', secure: true, expires: Date.now() })
                    .code(401).send({ error: 'USER_NOT_AUTHENTICATED' });
                break;
            case 'COOKIE_EXPIRED':
                res.setCookie('token', 'COOKIE_EXPIRED_DELETING_COOKIE', { path: '/', secure: true, expires: Date.now() })
                    .code(401).send({ error: 'USER_NOT_AUTHENTICATED' });
                break;
            default:
                res.code(500).send({ error: exception });
        }
    }
})

//MANAGING USERS
fastify.put('/api/admin/users/add', async (req, res) => {
    try {
        fastify.log.info('Starting user add procedure');

        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let user = req.body;
        if (!user ||
            !user.email ||
            !user.username ||
            !user.password ||
            typeof (user.email) !== 'string' ||
            typeof (user.username) !== 'string' ||
            typeof (user.password) !== 'string'
        ) throw 'MISSING_FIELDS';

        if (!String(user.email).toLowerCase().match(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/))
            throw 'INVALID_EMAIL_ADDRESS';

        let salt = crypto.randomBytes(64).toString('base64');
        let userHash = generateHash(user.password, salt);

        let uuid = getUuid(crypto.createHash('sha512').update(userHash + user.username + user.email + user.password).digest('base64'));

        let users = await conn.query('SELECT * FROM admins WHERE email=? OR name=?', [user.email, user.username]);
        if (users.length > 0) throw 'USERNAME_OR_EMAIL_TAKEN';

        sessions[uuid] = {};
        saveSessions();

        await conn.query('INSERT INTO admins (uuid, email, name, hash) VALUES (?, ?, ?, ?)', [uuid, user.email, user.username, salt + ':' + userHash]);
        fastify.log.info('User add procedure succesfull');
        res.code(201).send();
    } catch (exception) {
        fastify.log.error('User add procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'MISSING_FIELDS': case 'INVALID_EMAIL_ADDRESS': case 'USERNAME_OR_EMAIL_TAKEN':
                res.code(400);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.get('/api/admin/users/get', async (req, res) => {
    try {
        fastify.log.info('Starting users get procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let users = await conn.query('SELECT uuid, name, email FROM admins');
        fastify.log.info('Users get procedure succesfull');
        res.code(200).send(users);

    } catch (exception) {
        fastify.log.error('Users get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.delete('/api/admin/users/delete/*', async (req, res) => {
    try {
        fastify.log.info('Starting user delete procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';
        let url = req.url + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; //Add padding if the user uuid is to short, so that it does not throw an exception.

        let uuid = url.substring(24, 60);

        let users = await conn.query('SELECT * FROM admins WHERE uuid=?', [uuid]);
        if (users.length == 0) throw 'USER_DOES_NOT_EXIST';

        await conn.query('DELETE FROM admins WHERE uuid=?', [uuid]);

        if (sessions[uuid])
            delete (sessions[uuid]);
        saveSessions();

        fastify.log.info('User delete procedure succesfull');

        if (JSON.parse(fastify.unsignCookie(req.cookies.token).value).uuid == uuid) res.clearCookie('token');

        res.code(202).send();

    } catch (exception) {
        fastify.log.error('User delete procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'USER_DOES_NOT_EXIST':
                res.code(404);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.patch('/api/admin/users/setpassword', async (req, res) => {
    try {
        fastify.log.info('Starting user password set procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';
        let user = req.body;

        if (!user ||
            !user.uuid ||
            !user.newPassword ||
            typeof (user.uuid) !== 'string' ||
            typeof (user.newPassword) !== 'string'
        ) throw 'MISSING_FIELDS';



        let userResponse = await conn.query('SELECT * FROM admins WHERE uuid=?', [user.uuid]);
        if (userResponse.length == 0) throw 'USER_DOES_NOT_EXIST';

        let newSalt = crypto.randomBytes(64).toString('base64'); //Generate new salt, just for added security

        let hash = generateHash(user.newPassword, newSalt);

        try {
            await conn.query('START TRANSACTION');

            await conn.query('UPDATE admins SET hash=? WHERE uuid=?', [newSalt + ':' + hash, user.uuid]);

            sessions[user.uuid] = {};
            saveSessions();
            fastify.log.info('User password set procedure succesfull');
            res.code(202).send();
            await conn.query('COMMIT');
        } catch (exception) {
            await conn.query('ROLLBACK');
            throw exception
        }





    } catch (exception) {
        fastify.log.error('User password set procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'USER_DOES_NOT_EXIST':
                res.code(404);
                break;
            case 'MISSING_FIELDS':
                res.code(400);
                break;
            default:
                res.code(500);
                break;

        }
        res.send({ error: exception });
    }
})


//SETUP
fastify.delete('/api/admin/setup/resetall', async (req, res) => {
    try {
        fastify.log.info('Starting reset all procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        try {
            await conn.query('START TRANSACTION');

            await conn.query('UPDATE admins SET hash=? WHERE uuid=?', [newSalt + ':' + hash, user.uuid]);

            await conn.query('UPDATE state SET value=0');
            await conn.query('DELETE FROM classes');
            await conn.query('DELETE FROM logos');
            await conn.query('DELETE FROM tokens');
            await conn.query('DELETE FROM batch');
            await conn.query('ALTER TABLE logos AUTO_INCREMENT=1');
            await conn.query('ALTER TABLE classes AUTO_INCREMENT=1');

            let directory = config.pdfGeneration.pdfLocation;
            fs.readdir(directory, (err, files) => {
                if (err) throw err;

                for (const file of files) {
                    fs.unlink(path.join(directory, file), (err) => {
                        if (err) throw err;
                    });
                }
            });
            res.code(202).send();
            await conn.query('COMMIT');
        } catch (exception) {
            await conn.query('ROLLBACK');
            throw exception;
        }
    } catch (exception) {
        fastify.log.error('Reset all procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.post('/api/admin/setup/provision', async (req, res) => {

    try {
        fastify.log.info('Starting provision procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';


        let provisioned = (await conn.query('SELECT value FROM state WHERE id=\'provisioned\''))[0].value == 1;

        if (provisioned) throw 'ALREADY_PROVISIONED';

        let list = req.body;

        if (!list || !Array.isArray(list)) throw 'MISSING_FIELDS';
        let numberSet = new Set();
        for (let i = 0; i < list.length; i++) {
            if (!list[i] || !list[i].class || !list[i].logos || typeof (list[i].class) !== 'string' || !Array.isArray(list[i].logos)) throw 'MISSING_FIELDS';
            for (let j = 0; j < list[i].logos.length; j++)if (typeof (list[i].logos[j]) !== 'number') throw 'MISSING_FIELDS';
            for (let j = 0; j < list[i].logos.length; j++) {
                let num = list[i].logos[j];
                if (numberSet.has(num)) throw 'NUMBER_REPEATS';
                if (num > 1000 || num < 0) throw 'NUMBER_OUT_OF_RANGE';
                numberSet.add(num);
            }
        }

        let classes = new Set();
        for (let i = 0; i < list.length; i++) {
            if (classes.has(list[i].class)) throw 'CLASSES_SAME_NAME_ERROR';
            classes.add(list[i].class);
        }
        for (let i = 0; i < list.length; i++) {
            const classObject = list[i];
            let classUuid = getUuid(classObject.class + classObject.logos + crypto.randomBytes(32).toString());
            await conn.query('INSERT INTO classes (uuid, name) VALUES (?, ?)', [classUuid, classObject.class]);
            for (let j = 0; j < classObject.logos.length; j++) await conn.query('INSERT INTO logos (number, class) VALUES (?, ?)', [classObject.logos[j], classUuid]);
        }

        try {
            await conn.query('START TRANSACTION');
            await conn.query('UPDATE state SET value=1 WHERE id=\'provisioned\'');
            fastify.log.info('Provision procedure succesfull');
            await conn.query('COMMIT');
            res.code(201).send();
        } catch (exception) {
            fastify.log.error('Error provisioning ' + exception);
            await conn.query('ROLLBACK');
            throw exception;
        }




    } catch (exception) {
        fastify.log.error('Provision procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'ALREADY_PROVISIONED': case 'CLASSES_SAME_NAME_ERROR': case 'MISSING_FIELDS': case 'NUMBER_REPEATS': case 'NUMBER_OUT_OF_RANGE':
                res.code(400);
                break;
            default:
                res.code(500);
        }
        res.send({ error: exception });
    }

})


//MANAGING LOGOS
fastify.get('/api/admin/logos/get', async (req, res) => {
    try {
        fastify.log.info('Starting logos get procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';



        let list = [];
        let classes = await conn.query('SELECT uuid, name FROM classes ORDER BY number');
        for (let i = 0; i < classes.length; i++) {
            let classObject = classes[i];
            let logosResponse = await conn.query('SELECT number FROM logos WHERE class=?', [classObject.uuid]);
            let logos = [];
            for (let j = 0; j < logosResponse.length; j++)
                logos.push(logosResponse[j].number);
            logos.sort(function (a, b) { return a - b });
            list.push({
                class: classObject.uuid,
                name: classObject.name,
                logos: logos
            });

        }
        fastify.log.info('Logos get procedure succesfull');
        res.code(200).send(list);

    } catch (exception) {
        fastify.log.error('Logos get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})


//MAGING TOKENS
fastify.post('/api/admin/tokens/generate', async (req, res) => {
    try {
        fastify.log.info('Starting generate tokens procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';


        let provisioned = (await conn.query('SELECT value FROM state WHERE id=\'provisioned\''))[0].value == 1;
        if (!provisioned) throw 'NOT_PROVISIONED';

        let generateInfo = req.body;

        if (!generateInfo || !generateInfo.class || typeof (generateInfo.class) !== 'string' || typeof (generateInfo.number) !== 'number') throw 'MISSING_FIELDS';
        if (generateInfo.number <= 0 || generateInfo.number > config.pdfGeneration.maxTokensOneRequest) throw 'INVALID_NUMBER_OF_TOKENS';


        // check if class uuid exists

        let classResponse = await conn.query('SELECT uuid, name FROM classes WHERE uuid=?', [generateInfo.class]);
        if (classResponse.length == 0) throw 'CLASS_UUID_UNKNOWN';
        let className = classResponse[0].name;

        //check if every class uuid exists and also compute how much tokens we have to create


        //load current tokens to make sure we don't have any collisions while generating new ones.
        let existingTokensList = await conn.query('SELECT token FROM tokens');
        let existingTokens = new Set();
        for (let i = 0; i < existingTokensList.length; i++)existingTokens.add(existingTokensList[i].token);
        //load forbiddenTokens
        let forbiddenTokens = config.forbiddenTokens;
        for (let i = 0; i < forbiddenTokens.length; i++)
            existingTokens.add(forbiddenTokens[i]);


        const newToken = () => {
            const allowedChars = config.allowedTokenChars;
            const randomInt = () => {
                var buf = new Uint8Array(1);
                crypto.getRandomValues(buf);
                return buf[0];
            }
            let t1 = "", t2 = "";
            for (let i = 0; i < 4; i++)
                t1 += allowedChars[randomInt() % allowedChars.length];
            for (let i = 0; i < 4; i++)
                t2 += allowedChars[randomInt() % allowedChars.length];
            return t1 + "-" + t2;
        }

        let newTokens = [];

        for (let i = 0; i < generateInfo.number; i++) {
            let token = newToken();
            while (existingTokens.has(token)) token = newToken();

            existingTokens.add(token);
            newTokens.push(token);
        }
        fastify.log.info(newTokens);


        let currentTimeStamp = Math.round(Date.now() / 1000);
        let batchUuid = getUuid(crypto.createHash('sha512').update(Date.now().toString()).digest('base64'));

        for (let it = 0; it < newTokens.length; it++)
            await conn.query('INSERT INTO tokens (token, batchUuid, class) VALUES (?, ?, ?)', [newTokens[it], batchUuid, generateInfo.class])

        await conn.query('INSERT INTO batch (batchUuid, timestamp, class, number) VALUES (?, ?, ?, ?)', [batchUuid, currentTimeStamp, generateInfo.class, newTokens.length]);

        //generate pdf file

        const getQrSrc = (token) => `https://api.qrserver.com/v1/create-qr-code/?size=256&data=${encodeURIComponent(config.pdfGeneration.votingUrl.replace('{{token}}', token))
            }&format=svg&margin=0&ecc=M`;

        let tokenList = [];
        for (let i = 0; i < newTokens.length; i++)
            tokenList.push({
                token: newTokens[i],
                qrSrc: getQrSrc(newTokens[i]),
            });

        try {
            let renderClass = [{
                className: className,
                tokens: tokenList
            }];

            let renderedHtml = renderHTML(renderClass);

            const browser = await puppeteer.launch({ executablePath: config.pdfGeneration.chromiumPath, headless: 'new' });
            const page = await browser.newPage();
            fastify.log.info('Browser launched!')
            await page.setContent(renderedHtml, { waitUntil: 'networkidle0' });

            const pdf = await page.pdf({
                path: path.join(config.pdfGeneration.pdfLocation, batchUuid + '.pdf'),
                margin: { top: '100px', right: '50px', bottom: '100px', left: '50px' },
                printBackground: true,
                format: 'A4',
            });

            await browser.close();
            fastify.log.info('PDF generated for ' + batchUuid);
        }
        catch (exception) {
            fastify.log.error(exception);
            throw 'PDF_GENERATION_ISSUE_CHECK_LOG'
        }

        res.code(201).send({
            batchUuid: batchUuid,
            timestamp: currentTimeStamp,
            class: generateInfo.class,
            className: className,
            pdfUrl: config.pdfGeneration.pdfLink.replace('{{uuid}}', batchUuid),
            tokens: newTokens
        });
    } catch (exception) {
        fastify.log.error('Generate tokens procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'NOT_PROVISIONED': case 'INVALID_NUMBER_OF_TOKENS': case 'MISSING_FIELDS':
                res.code(400);
                break;
            case 'CLASS_UUID_UNKNOWN':
                res.code(404);
                break;
            default:
                res.code(500);
                break;

        }
        res.send({ error: exception });
    }
})
fastify.get('/api/admin/tokens/get', async (req, res) => {
    try {
        fastify.log.info('Starting tokens get procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let batches = await conn.query('SELECT batchUuid, timestamp, class FROM batch');

        let listToReturn = [];
        for (let i = 0; i < batches.length; i++) {
            let batchUuid = batches[i].batchUuid;

            let tokensResponse = await conn.query('SELECT token, vote FROM tokens WHERE batchUuid=?', batchUuid);
            let list = [];
            for (let j = 0; j < tokensResponse.length; j++)
                list.push({
                    token: tokensResponse[j].token,
                    used: tokensResponse[j].vote != null
                });
            let className = (await conn.query('SELECT name FROM classes WHERE uuid=?', batches[i].class))[0].name
            listToReturn.push({
                batchUuid: batchUuid,
                timestamp: batches[i].timestamp,
                class: batches[i].class,
                className: className,
                tokens: list
            });
        }

        fastify.log.info('Tokens get procedure succesfull.')
        res.code(200).send(listToReturn);

    } catch (exception) {
        fastify.log.error('Tokens get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})

fastify.delete('/api/admin/tokens/revoke/*', async (req, res) => {
    try {
        fastify.log.info('Starting tokens revoke procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let batchUuid = (req.url + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx').substring(25, 61); //add padding if the uuid is too short

        //check if uuid exists;
        let batchResponse = await conn.query('SELECT * FROM batch WHERE batchUuid=?', batchUuid);
        if (batchResponse.length == 0) throw 'BATCH_UUID_NOT_FOUND';

        let tokensToRevoke = await conn.query('SELECT token, vote FROM tokens WHERE batchUuid=?', batchUuid);
        await conn.query('DELETE FROM tokens WHERE batchUuid=?', batchUuid);
        let votesToRevoke = [];
        for (let i = 0; i < tokensToRevoke.length; i++)
            if (tokensToRevoke[i].vote != null) {
                let list = JSON.parse(tokensToRevoke[i].vote);
                for (let j = 0; j < list.length; j++)votesToRevoke.push(list[j]);
            }
        fastify.log.info('Revoking tokens and reverting votes');

        try {
            await conn.query('START TRANSACTION');
            for (let i = 0; i < votesToRevoke.length; i++)
                await conn.query('UPDATE logos SET points=points+? WHERE number=?', [votesToRevoke[i].points * -1, votesToRevoke[i].logo]);
            console.log('revoking numbers');
            for (let i = 0; i < votesToRevoke.length; i++)
                await conn.query('UPDATE logos SET pointsCounter' + Math.abs(votesToRevoke[i].points).toString() + (votesToRevoke[i].points > 0 ? 'pos' : 'neg') + '=pointsCounter' + Math.abs(votesToRevoke[i].points).toString() + (votesToRevoke[i].points > 0 ? 'pos' : 'neg') + '-1 WHERE number=?', [
                    votesToRevoke[i].logo]);
            console.log('revoked numbers');
            await conn.query('DELETE FROM batch WHERE batchUuid=?', batchUuid);

            fs.unlink(path.join(config.pdfGeneration.pdfLocation, batchUuid + '.pdf'), (err) => {
                if (err) throw err;
            });



            await conn.query('COMMIT');
            res.code(202).send();
        } catch (exception) {
            fastify.log.error('Error revoking tokens ' + exception);
            await conn.query('ROLLBACK');
            throw exception;
        }



    } catch (exception) {
        fastify.log.error('Tokens revoke procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'BATCH_UUID_NOT_FOUND':
                res.code(404);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }









})
fastify.get('/api/admin/tokens/pdf/*', async (req, res) => {
    try {
        fastify.log.info('Starting pdf get procedure')
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let fileName = req.url.substring(22);
        let fullPath = path.join(config.pdfGeneration.pdfLocation, fileName);

        if (fs.existsSync(fullPath)) {
            const bufferIndexHtml = fs.readFileSync(fullPath);
            fastify.log.info('Pdf get procedure succesfull');
            res.type('application/pdf').code(200).send(bufferIndexHtml);
        } else throw 'PDF_NOT_FOUND';
    } catch (exception) {
        fastify.log.error('Pdf get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'PDF_NOT_FOUND':
                res.code(404);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})

//MANAGING VOTING
fastify.post('/api/admin/voting/start', async (req, res) => {
    try {
        fastify.log.info('Starting voting')
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';
        let provisioned = (await conn.query('SELECT value FROM state WHERE id=\'provisioned\''))[0].value == 1;
        if (!provisioned) throw 'NOT_PROVISIONED';

        try {
            await conn.query('START TRANSACTION');
            await conn.query('UPDATE state SET value=1 WHERE id=\'voting\'');
            fastify.log.info('Voting start procedure succesfull');

            await conn.query('COMMIT');
            res.code(202).send();
        } catch (exception) {
            fastify.log.error('Error starting voting ' + exception);
            await conn.query('ROLLBACK');
        }

    } catch (exception) {
        fastify.log.error('Starting voting failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'NOT_PROVISIONED':
                res.code(400);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.post('/api/admin/voting/stop', async (req, res) => {
    try {
        fastify.log.info('Stopping voting')
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';
        let provisioned = (await conn.query('SELECT value FROM state WHERE id=\'provisioned\''))[0].value == 1;
        if (!provisioned) throw 'NOT_PROVISIONED';

        try {
            await conn.query('START TRANSACTION');
            await conn.query('UPDATE state SET value=0 WHERE id=\'voting\'');
            fastify.log.info('Voting stop procedure succesfull');

            await conn.query('COMMIT');
            res.code(202).send();
        } catch (exception) {
            fastify.log.error('Error stoping voting ' + exception);
            await conn.query('ROLLBACK');
        }

    } catch (exception) {
        fastify.log.error('Stopping voting failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            case 'NOT_PROVISIONED':
                res.code(400);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.get('/api/admin/voting/results/get', async (req, res) => {
    try {
        fastify.log.info('Starting results get procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let resultsResponse = await conn.query('SELECT * FROM logos ORDER BY points DESC');

        let classesList = await conn.query('SELECT * FROM classes');
        let classes = {};
        for (let i = 0; i < classesList.length; i++)
            classes[classesList[i].uuid] = classesList[i];

        let pointsResponse = await conn.query('SELECT points FROM logos ORDER BY points DESC');
        let cnt = {}, ranking = {}, count = 1;
        for (let i = 0; i < pointsResponse.length; i++) {
            cnt[pointsResponse[i].points] = (cnt[pointsResponse[i].points]) ? cnt[pointsResponse[i].points] + 1 : 1;

        }
        let pnts = await conn.query('SELECT points FROM logos GROUP BY points ORDER BY points DESC')
        for (let i = 0; i < pnts.length; i++) {
            ranking[pnts[i].points] = count;
            count += cnt[pnts[i].points];
        }

        let results = [];
        for (let i = 0; i < resultsResponse.length; i++) {
            let obj = {
                number: resultsResponse[i].number,
                class: classes[resultsResponse[i].class],
                totalPoints: resultsResponse[i].points,
                detailedPoints: [],
                ranking: ranking[resultsResponse[i].points]
            };
            for (const key in resultsResponse[i])
                if (key.startsWith('pointsCounter')) {
                    let str = key.substring(13);
                    let num = str.substring(0, str.length - 3);
                    let sign = str.substring(str.length - 3, str.length) == 'pos' ? 1 : -1;
                    let points = num * sign;
                    obj.detailedPoints.push({
                        points: points,
                        count: resultsResponse[i][key]
                    })
                }
            results.push(obj);

        }
        fastify.log.info('Results get procedure succesfull');
        res.code(200).send(results);

    } catch (exception) {
        fastify.log.error('Results get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})
fastify.get('/api/admin/voting/results/results.csv', async (req, res) => {
    try {
        fastify.log.info('Starting results csv get procedure');
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';

        let resultsResponse = await conn.query('SELECT * FROM logos ORDER BY points DESC');

        let classesList = await conn.query('SELECT * FROM classes');
        let classes = {};
        for (let i = 0; i < classesList.length; i++)
            classes[classesList[i].uuid] = classesList[i];

        let pointsResponse = await conn.query('SELECT points FROM logos ORDER BY points DESC');
        let cnt = {}, ranking = {}, count = 1;
        for (let i = 0; i < pointsResponse.length; i++) {
            cnt[pointsResponse[i].points] = (cnt[pointsResponse[i].points]) ? cnt[pointsResponse[i].points] + 1 : 1;

        }
        let pnts = await conn.query('SELECT points FROM logos GROUP BY points ORDER BY points DESC')
        for (let i = 0; i < pnts.length; i++) {
            ranking[pnts[i].points] = count;
            count += cnt[pnts[i].points];
        }

        let csvString = '"Miejsce","Klasa","Numer logotypu","Liczba punktów"';
        for (let i = 0; i < config.allowedPoints.length; i++)
            csvString += ',"Pnkt ' + config.allowedPoints[i] + '"';
        csvString += '\n';

        for (let i = 0; i < resultsResponse.length; i++) {
            let tmpString = '"' + ranking[resultsResponse[i].points] + '","' +
                classes[resultsResponse[i].class].name + '","' +
                resultsResponse[i].number + '","' +
                resultsResponse[i].points + '"';
            for (const key in resultsResponse[i])
                if (key.startsWith('pointsCounter')) {
                    tmpString += ',"' + resultsResponse[i][key] + '"'
                }
            csvString += tmpString + '\n';

        }
        fastify.log.info('Results get csv procedure succesfull');
        res.code(200)
            .header('Content-Type', 'application/CSV; charset=utf-8')
            .header('Content-Disposition', 'attachment;filename=Wyniki.csv')
            .send(csvString);

    } catch (exception) {
        fastify.log.error('Results get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})

//MANAGING CLASSES
fastify.get('/api/admin/classes/get', async (req, res) => {
    try {
        fastify.log.info('Starting classes get procedure.')
        if (!verifyToken(req.cookies.token)) throw 'USER_NOT_AUTHENTICATED';



        let list = await conn.query('SELECT uuid, name FROM classes');
        let byName = {}, byUuid = {}, classList = [];
        for (let i = 0; i < list.length; i++) {
            byName[list[i].name] = list[i].uuid;
            byUuid[list[i].uuid] = list[i].name;
            classList.push(list[i].uuid);
        }


        fastify.log.info('Classes get procedure succesfull');
        res.code(200).send({
            list: classList,
            byUuid: byUuid,
            byName: byName
        });
    } catch (exception) {
        fastify.log.error('Classes get procedure failed with exception ' + exception);
        switch (exception) {
            case 'USER_NOT_AUTHENTICATED':
                res.code(401);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})


//USER THINGS
fastify.get('/api/user/getinfo', async (req, res) => {
    try {
        let token = new URL('https://example.com' + req.url).searchParams.get('token');
        if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(token)) token = 'xxxxxxxxxxxx';
        fastify.log.info('Starting vote info get procedure for token=', token);


        let provisioned = (await conn.query('SELECT value FROM state WHERE id=\'provisioned\''))[0].value == 1;
        let voting = (await conn.query('SELECT value FROM state WHERE id=\'voting\''))[0].value == 1;

        let availableLogos = [], forbiddenLogos = [], used = null, found = false, codeClass = null;

        if (provisioned && voting && token) {

            let tokenResponse = await conn.query('SELECT * FROM tokens WHERE token=?', [token]);
            fastify.log.info(tokenResponse);
            if (tokenResponse.length == 1) {

                let tokenObject = tokenResponse[0];
                found = true;
                used = tokenObject.vote != null;
                codeClass = (await conn.query('SELECT name FROM classes WHERE uuid=?', [tokenObject.class]))[0].name;
                let logos = await conn.query('SELECT number, class FROM logos ORDER BY number');
                for (let i = 0; i < logos.length; i++) {
                    if (logos[i].class == tokenObject.class)
                        forbiddenLogos.push(logos[i].number);
                    else
                        availableLogos.push(logos[i].number);
                }

            }
        }
        let responseObject = null;
        if (provisioned && voting && token)
            responseObject = {
                provisioned: provisioned,
                voting: voting,
                found: found,
                goodlood: "jeszcze jak!",
                message: config.message
            }
        else
            responseObject = {
                provisioned: provisioned,
                voting: voting,
                goodlood: "jeszcze jak!",
                message: config.message
            };

        if (found) {
            responseObject.used = used;
            responseObject.class = codeClass;
            responseObject.availableLogos = availableLogos;
            responseObject.forbiddenLogos = forbiddenLogos;
        }
        fastify.log.info('Get vote info procedure succesfull');
        res.code(200).send(responseObject);
    }
    catch (exception) {
        fastify.log.error('Get vote info procedure failed with exception ' + exception);
        res.code(500).send({ error: exception });
    }
})
fastify.post('/api/user/vote', async (req, res) => {
    try {
        //check if provisioned and voting
        let provisioned = (await conn.query('SELECT value FROM state WHERE id=\'provisioned\''))[0].value == 1;
        let voting = (await conn.query('SELECT value FROM state WHERE id=\'voting\''))[0].value == 1;
        if (!provisioned) throw 'NOT_PROVISIONED';
        if (!voting) throw 'NOT_VOTING';

        let vote = req.body;

        if (!vote ||
            !vote.token ||
            !vote.votes ||
            !Array.isArray(vote.votes) ||
            typeof (vote.token) !== 'string'
        ) throw 'MISSING_FIELDS';
        for (let i = 0; i < vote.votes.length; i++)if (!vote.votes[i] || typeof (vote.votes[i].logo) !== 'number' || typeof (vote.votes[i].points) !== 'number') throw 'MISSING_FIELDS';

        //check if token is valid and not used
        if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(vote.token)) throw 'INVALID_TOKEN';
        let tokenResponse = await conn.query('SELECT * FROM tokens WHERE token=?', [vote.token]);

        if (tokenResponse.length == 0) throw 'INVALID_TOKEN';
        if (tokenResponse[0].vote != null) throw 'TOKEN_ALREADY_USED';

        //check if user has not modified points to maybe add 1000 to their favorite logo
        let votedPoints = [];
        for (let i = 0; i < vote.votes.length; i++)votedPoints.push(vote.votes[i].points);
        votedPoints.sort(function (a, b) { return a - b });

        if (votedPoints.length != config.allowedPoints.length) throw 'INVALID_VOTE_POINTS';
        for (let i = 0; i < votedPoints.length; i++)if (votedPoints[i] != config.allowedPoints[i]) throw 'INVALID_VOTE_POINTS';

        //check if user has chosen correct logos
        let allowedLogosList = await conn.query('SELECT number FROM logos WHERE class!=?', [tokenResponse[0].class]);
        let allowedLogos = new Set();
        for (let i = 0; i < allowedLogosList.length; i++)allowedLogos.add(allowedLogosList[i].number);
        for (let i = 0; i < vote.votes.length; i++)
            if (!allowedLogos.has(vote.votes[i].logo)) throw 'LOGO_NOT_ALLOWED';

        //check if user does not cast multiple votes for the same logo
        let logosSet = new Set();
        for (let i = 0; i < vote.votes.length; i++) {
            if (logosSet.has(vote.votes[i].logo)) throw 'DUPLICATE_VOTE_FOR_SAME_LOGO';
            logosSet.add(vote.votes[i].logo);
        }
        //vote is correct, store it and count points;
        try {
            await conn.query('START TRANSACTION');
            let userVote = JSON.stringify(vote.votes);
            await conn.query('UPDATE tokens SET vote=? WHERE token=?', [userVote, vote.token])
            for (let i = 0; i < vote.votes.length; i++)
                await conn.query('UPDATE logos SET points=points+? WHERE number=?', [vote.votes[i].points, vote.votes[i].logo]);
            for (let i = 0; i < vote.votes.length; i++)
                await conn.query('UPDATE logos SET pointsCounter' + Math.abs(vote.votes[i].points).toString() + (vote.votes[i].points > 0 ? 'pos' : 'neg') + '=pointsCounter' + Math.abs(vote.votes[i].points).toString() + (vote.votes[i].points > 0 ? 'pos' : 'neg') + '+1 WHERE number=?', [
                    vote.votes[i].logo]);
            await conn.query('COMMIT');
            res.code(202).send();
        } catch (exception) {
            await conn.query('ROLLBACK');
            throw exception;
        }
    } catch (exception) {
        fastify.log.error('Logos get procedure failed with exception ' + exception);
        switch (exception) {
            case 'MISSING_FIELDS':
            case 'NOT_PROVISIONED':
            case 'NOT_VOTING':
            case 'INVALID_TOKEN':
            case 'TOKEN_ALREADY_USED':
            case 'INVALID_VOTE_POINTS':
            case 'LOGO_NOT_ALLOWED':
            case 'DUPLICATE_VOTE_FOR_SAME_LOGO':
                res.code(400);
                break;
            default:
                res.code(500);
                break;
        }
        res.send({ error: exception });
    }
})


//OTHER BITS
function generateHash(password, salt) {
    let pepper = secrets.pepper;
    for (let i = 0; i < 100000; i++)
        password = crypto.createHash('sha512').update(salt + password + pepper).digest('base64');
    return password;
}
let verifyToken = (token) => {
    if (token && fastify.unsignCookie(token).valid && JSON.parse(fastify.unsignCookie(token).value).admin) {
        let object = JSON.parse(fastify.unsignCookie(token).value);
        if (sessions[object.uuid] && sessions[object.uuid][object.nonce]) return object;
        return null;
    }
    else return environment == '--test' ? 'TEST_ONLY' : null;
}
async function saveSessions() {
    try {
        await conn.query('START TRANSACTION');
        await conn.query('UPDATE sessions SET value=? WHERE id=\'sessions\'', JSON.stringify(sessions));
        await conn.query('COMMIT');
    } catch (exception) {
        fastify.log.error('Error saving sessions ' + exception);
        await conn.query('ROLLBACK');
    }
}


start()
