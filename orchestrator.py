# Sure, here is some sample Python code that uses the Docker SDK for Python to start a Docker container and wait until it ends:

import docker

client = docker.from_env()

# Start a container
container = client.containers.run("image_name", detach=True)

# Wait for the container to exit
exit_code = container.wait()['StatusCode']

# Remove the container
container.remove()

print("Container exited with code", exit_code)
# In this code, we first create a Docker client using the docker.from_env() method. Then, we start a container using the client.containers.run() method,
# passing the name of the Docker image we want to run.

# We set detach=True to run the container in the background, so the code doesn't block while the container is running.

# Next, we wait for the container to exit using the container.wait() method, which blocks until the container is stopped.
# This method returns a dictionary containing the exit code of the container, which we extract with the ['StatusCode'] key.

# Finally, we remove the container with the container.remove() method, and print out the exit code of the container.