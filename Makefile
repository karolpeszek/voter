build:
	sudo docker build -t karolpeszek/voter:latest . 
run:
	sudo docker run --net=host -v /etc/voter:/config --restart unless-stopped -d karolpeszek/voter:latest
clean:
	sudo docker image rm karolpeszek/voter:latest
push:
	sudo docker push karolpeszek/voter:latest
