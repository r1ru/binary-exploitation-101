#!/bin/bash -eux

sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    git \
    libssl-dev \
    libffi-dev \
    build-essential \
    curl \
    wget \
    liblzma-dev \
    pkg-config \
    patchelf \
    elfutils \
    zstd \
    gdbserver \
    tmux

# Install [pwntools](https://docs.pwntools.com/en/stable/install.html#python3).
sudo pip3 install --break-system-packages pwntools

# Install [pwndbg](https://pwndbg.re/pwndbg/latest/setup/#installing-pwndbg-gdb).
curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb

# FIXME
sudo ln -s /usr/local/bin/pwndbg /usr/local/bin/gdb

# Install [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).
curl https://sh.rustup.rs -sSf | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

# Install [pwninit](https://github.com/io12/pwninit).
cargo install pwninit

# Install [ropr](https://github.com/Ben-Lichtman/ropr).
cargo install ropr
