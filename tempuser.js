const mariadb = require('mariadb');
const getUuid = require('uuid-by-string');
const crypto = require('crypto');

const config = require("/config/config.json");
const secrets = require("/config/secrets.json");

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

async function newuser() {
    console.log('Starting temp user add procedure');

    let conn = await mariadb.createPool(config.sql);
    await conn.query('USE ' + config.sql.database);

    const user = {
        username: crypto.randomBytes(16).toString('hex') + '-temporal',
        password: crypto.randomBytes(16).toString('hex'),
        email: 'temporal@user.example'
    }

    let salt = crypto.randomBytes(64).toString('base64');
    let userHash = generateHash(user.password, salt);

    let uuid = getUuid(crypto.createHash('sha512').update(userHash + user.username + user.email + user.password).digest('base64'));


    await conn.query('START TRANSACTION');

    await conn.query('INSERT INTO admins (uuid, email, name, hash) VALUES (?, ?, ?, ?)', [uuid, user.email, user.username, salt + ':' + userHash]);
    console.log('User add procedure succesfull');
    console.log('username: ' + user.username);
    console.log('password: ' + user.password);
    console.log('PLEASE RESTART THE CONTAINER!!!');
    await conn.query('COMMIT');
    process.exit(0);
}
newuser();
