# Hullproof Action image. Everything that runs in it is pinned:
#   the base image by digest, Node and the three Go scanners by version and sha256 (per CPU architecture), Semgrep and its Python
#   dependencies by version and wheel hash (semgrep.lock), and the engine by the sha256 of its tarball.
# The operating system packages (git, Python, certificates) come from the pinned Debian image through apt, which does not hash pin them.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ARG NODE_VERSION=22.23.2
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.75.0
ARG OSV_VERSION=2.6.0
ARG ENGINE_SHA256=028709bea0b84a2227f9676ddef4ad64e0814efa5b83b6d37237f286b7054d98

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Each download is checked against a sha256 written here before it is unpacked. A mismatch stops the build.
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
      amd64) node_arch=x64;   node_sha=d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307; \
             gl_arch=x64;     gl_sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb; \
             tv_arch=64bit;   tv_sha=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f; \
             osv_arch=amd64;  osv_sha=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 ;; \
      arm64) node_arch=arm64; node_sha=fff4078c5def658577f92c88db7db3bc0072924bfb93fe52c1e744a54e94abb8; \
             gl_arch=arm64;   gl_sha=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080; \
             tv_arch=ARM64;   tv_sha=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3; \
             osv_arch=arm64;  osv_sha=2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4 ;; \
      *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" "$node_sha"; \
    tar -xJf node.tar.xz -C /usr/local --strip-components=1 --no-same-owner; \
    fetch gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" "$gl_sha"; \
    tar -xzf gitleaks.tgz -C /usr/local/bin gitleaks; \
    fetch trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz" "$tv_sha"; \
    tar -xzf trivy.tgz -C /usr/local/bin trivy; \
    fetch osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${osv_arch}" "$osv_sha"; \
    install -m 0755 osv-scanner /usr/local/bin/osv-scanner; \
    rm -f /tmp/*.tgz /tmp/*.tar.xz /tmp/osv-scanner

COPY semgrep.lock /tmp/semgrep.lock
RUN python3 -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --require-hashes --no-deps --only-binary=:all: -r /tmp/semgrep.lock \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && rm /tmp/semgrep.lock

COPY engine/hullproof-engine-0.4.0.tgz /tmp/engine.tgz
RUN echo "${ENGINE_SHA256}  /tmp/engine.tgz" | sha256sum -c - \
 && npm install --global --ignore-scripts --no-audit --no-fund /tmp/engine.tgz \
 && rm /tmp/engine.tgz

COPY kit /opt/hullproof/kit
COPY src/run.mjs /opt/action/run.mjs

ENV HULLPROOF_KIT_DIR=/opt/hullproof/kit \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

ENTRYPOINT ["node", "/opt/action/run.mjs"]
