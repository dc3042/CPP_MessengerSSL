FROM ubuntu:20.04
  
RUN mkdir /home/server_tree

RUN apt-get update && \
  	apt-get -y upgrade && \
  	apt-get install -y build-essential && \
  	apt-get install -y libssl-dev

COPY server_tree /home/server_tree

CMD ["bash"]
