# Encrypted client / server messaging system

The security architecture of this system uses sandboxing to prevent vulnerabilities from spreading to the host machine. Docker is used to containerize the server application and act as the sandbox. To easily install the software including Docker on Ubuntu, follow the below steps from the root project directory. We will use an Ubuntu base image to create our container. From your Google Cloud VM terminal, execute the following commands to create a tree for two different users. We will later send / recieve a message from one to the other.

	make install
	make server_tree
	make client_tree TREE=addleness-tree
	make client_tree TREE=analects-tree
	make build

Docker is now installed and the image has been built. The source code / binaries of the server system were copied to your Docker container during the image building process. It is located in home/server_tree. Now let's start the Docker container in a Google Cloud VM terminal to begin sending communcations between the client and server.

# Start the server:
1) In the same terminal you are currently in, run 
```
docker run -p 443:443 -it server_tree
```
This will start your container and enter the container's shell.
2) cd to '/home/server_tree'
3) Run 
```
./bin/server
```
4) Enter server password: 'serverpassword'

Your server is now running within the Docker container. Now let's start the client in a separate Google Cloud VM terminal.

# Start the client:
1) Open another Google Cloud VM terminal on the same Google VM. Use the 'Open in browser window' option.
2) Run 'docker ps' to obtain the running container's ID. It should look something like this: 13e2a8191b8c
3) Run 
```
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' [your-container-id]
```
replacing the container ID value found in step 2. This obtains the IP address for the server container which will be used later.

# Run the getcert program for each client:
1) cd to addleness-tree
2) Run 
```
./bin/getcert 172.17.0.2
```
replacing the IP address found from the steps above.
3) Enter the chosen user's ID (e.g. addleness)
4) Enter the chosen user's password (e.g. Cardin_pwns)
5) You will see a 200 OK response on the client side with the certificate returned from the server. On the server terminal, you will see the user who requested the certificate followed by the corresponding public key.
6) Repeat the same for ../analects-tree, by first cd'ing that directory and repeating from step 2.
	* Make sure to use the correct ID (analects) and password (pickerel_symbiosis) this time though

# Run the sendmsg program:
1) cd to ../addleness-tree
1) Run 
```
./bin/sendmsg 172.17.0.2 analects
```
replacing the IP address found from the steps above.
2) Enter password for addleness, the one sending the message ('Cardin_pwns')
3) Enter whatever message you like.

# Run the recvmsg program:
1) cd to analects-tree
3) Run 
```
./bin/recvmsg 172.17.0.2
```
4) Enter the password for analects (pickerel_symbiosis). The message will appear and be deleted from the server. Attempting this again will return no message since it was deleted.

Note that the sendmsg program can take multiple recipients as arguments. You will just have to create a tree for each of those users, and run the getcert command within each user tree before attempting to send messages to them.

# Run tests:
1) From the root project directory, run 'make server_tree'
2) cd to server_tree
3) Run 'sudo ./bin/server' and enter your sudo password, then server password: 'serverpassword'
4) In another terminal, run 'make test' from the root project directory to execute the test suite.
