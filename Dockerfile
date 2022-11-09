# Build image from Ubuntu repository
FROM ubuntu:22.04

# Creation of MasterThesis directory
RUN mkdir -p MasterThesis

# Copy directory inside the container
ADD . /MasterThesis

# The image build will operate from the /MasterThesis directory
WORKDIR /MasterThesis/ghidra_10.1.5_PUBLIC/support

# Define default command to run at container startup
# CMD ["analyzeHeadless", "/MasterThesis/", "MasterThesis", "-process", "main-bin", "-scriptPath", "/MasterThesis/headless_scripts/", "-postScript", "disassembler.py", "/MasterThesis/output.txt"]
CMD analyzeHeadless