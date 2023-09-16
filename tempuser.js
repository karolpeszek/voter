const mariadb = require('mariadb');
const getUuid = require('uuid-by-string');
const crypto = require('crypto');

const config = require("/config/config.json");
const secrets = require("/config/secrets.json");

function generateHash(password, salt) {
    let pepper = secrets.pepper, hash = secrets.hashInit;
    for (let i = 0; i < 100000; i++)
        hash = crypto.createHash('sha512').update(salt).update(password).update(hash).update(pepper).digest('base64');
    return hash;
}

async function newuser() {
    console.log('Starting temp user add procedure');

    let conn = await (await mariadb.createPool(config.sql)).getConnection();
    await conn.query('USE ' + config.sql.database);

    const user = {
        username: crypto.randomBytes(16).toString('hex') + '-temporal',
        password: crypto.randomBytes(16).toString('hex'),
        email: 'temporal@user.example'
    }

    let salt = crypto.randomBytes(64).toString('base64');
    let uuid = getUuid(crypto.randomBytes(64).toString('base64'));
    let userHash = generateHash(user.password, salt + user.email + user.username + uuid);


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
