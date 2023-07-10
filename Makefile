build:
	sudo docker buildx build --platform=linux/amd64,linux/arm64 -t karolpeszek/voterlatest . --push
run:
	sudo docker run --net=host -v /etc/config:/config -d karolpeszek/voter:latest
clean:
	sudo docker image rm karolpeszek/voter:latest
