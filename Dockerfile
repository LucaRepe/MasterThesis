# Build image from python repository
FROM python:3.10

# Creation of MasterThesis directory and subdirectories
RUN mkdir -p MasterThesis \
    && mkdir -p MasterThesis/Pickles \
    && mkdir -p MasterThesis/Pickles/Complete

ADD mainTechVS.exe /MasterThesis

# Install OpenJDK17
# RUN apt-get update \
    # && apt-get install -y openjdk-17-jdk

# Install python packages
# RUN pip install r2pipe networkx xxhash matplotlib angr

# Install wine
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install --no-install-recommends --assume-yes wine \
    && apt-get install wine32 \
    && winecfg

# Install python packages inside wine
RUN wine cmd \
    && python -m pip install xxhash matplotlib networkx

# Add tools inside the container
# ADD /Headless_scripts /MasterThesis/Headless_scripts
ADD /Tools/IDAPro7.7/ /MasterThesis/Tools/IDAPro7.7
# ADD /Tools/ghidra_10.2.3_PUBLIC/ /MasterThesis/Tools/ghidra_10.2.3_PUBLIC
# ADD /Tools/radare2/ /MasterThesis/Tools/radare2
# ADD /Tools/Ghidrathon-2.0.1 /Tools/Ghidrathon-2.0.1

# The image build will operate from the MasterThesis directory
# WORKDIR /MasterThesis

# Run installation of radare2
# RUN Tools/radare2/sys/install.sh