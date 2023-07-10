build:
	sudo docker build -t karolpeszek/voter:latest . --push
run:
	sudo docker run --net=host -v /etc/voter:/config --restart unless-stopped -d karolpeszek/voter:latest
clean:
	sudo docker image rm karolpeszek/voter:latest
