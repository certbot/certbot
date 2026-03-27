# Use a base image for the target architecture (e.g., Ubuntu for ARM64)
FROM --platform=linux/arm64 ubuntu:22.04 AS qemu_build

WORKDIR /app

# Install QEMU dependencies and build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libglib2.0-dev \
    libfdt-dev \
    libpixman-1-dev \
    zlib1g-dev \
    qemu-system \
    qemu-user-static # Installs the QEMU binaries inside the container

# Clone QEMU source code (adjust to snap-specific sources if needed)
RUN git clone https://github.com .

# Configure and build QEMU for the target architecture (since we're already in an emulated ARM64 env)
RUN ./configure --target-list=arm-softmmu,aarch64-softmmu # Example targets
RUN make
