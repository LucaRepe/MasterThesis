# Build image from openjdk repository
FROM openjdk:11-slim

# Creation of MasterThesis directory
RUN mkdir -p MasterThesis

# Copy directory inside the container
ADD . /MasterThesis

# The image build will operate from the /MasterThesis directory
WORKDIR /MasterThesis

# Define command to run analyzeHeadless
CMD ["./ghidra_10.2.2_PUBLIC/support/analyzeHeadless", "/MasterThesis/", "GhidraProject", "-import", "main-bin", "-scriptPath", "/MasterThesis/ghidra_10.2.2_PUBLIC/support/", "-postScript", "disassemblerGhidra.py", "/output.txt", "-deleteProject"]

# Define command to visualize output
RUN cat output.txt