# Remote demo machine: Herdr is preinstalled; Attached is installed on camera.
# Rebuild without the cache to pick up the latest stable Herdr.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash ca-certificates curl passwd xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -fsSL https://herdr.dev/install.sh \
        --output /tmp/install-herdr.sh \
    && HERDR_INSTALL_DIR=/usr/local/bin sh /tmp/install-herdr.sh \
    && rm /tmp/install-herdr.sh \
    && herdr --version

# Root is confined to this disposable container, matching docker cp's owner.
WORKDIR /root
ENV PATH="/root/.local/bin:${PATH}" TERM=xterm-256color
RUN mkdir -p .config/herdr \
    && printf 'onboarding = false\n\n[theme]\nname = "terminal"\n' \
        > .config/herdr/config.toml \
    && printf 'export PATH="$HOME/.local/bin:$PATH"\nexport PS1="\\[\\e[38;5;114m\\]office \\[\\e[0m\\]$ "\n' \
        > .bashrc

# No sshd, exposed ports, credentials, or preconfigured Attached account.
CMD ["sleep", "infinity"]
