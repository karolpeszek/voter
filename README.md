Voter API for V LO im. Augusta Witkowskiego

How to use?

1. Install docker
2. Create a database with the voter.sql file. Create a user for the database.
3. Add the database credentials to config.json
4. Generate random gibberish as your pepper and salt in secrets.json
5. Move everything from etc/voter to /etc/voter
6. Run docker pull karolpeszek/voter:latest
7. Run docker run --net=host -v /etc/voter:/config -d karolpeszek/voter:latest
8. Enojoy!
