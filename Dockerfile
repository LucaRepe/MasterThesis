# Build image from openjdk repository
FROM python:3.9

# RUN apt-get -y install git

RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt-get install --no-install-recommends --assume-yes wine

## Install wine and winetricks
# RUN apt-get -y install --install-recommends winehq-devel

# Creation of MasterThesis directory and subdirectories
RUN mkdir -p MasterThesis
RUN mkdir -p MasterThesis/Pickles
RUN mkdir -p MasterThesis/Pickles/Complete

# RUN pip install r2pipe networkx xxhash matplotlib angr

# Copy directory inside the container
ADD /Headless_scripts /MasterThesis
ADD /../../IDAPro7.7/ /MasterThesis/IDAPro7.7

# The image build will operate from the /MasterThesis directory
WORKDIR /MasterThesis
RUN git clone https://github.com/radareorg/radare2
RUN radare2/sys/install.sh