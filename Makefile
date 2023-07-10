build:
	sudo docker build -t karolpeszek/voterlatest . --push
run:
	sudo docker run --net=host -v /etc/config:/config --restart unless-stopped -d karolpeszek/voter:latest
clean:
	sudo docker image rm karolpeszek/voter:latest
