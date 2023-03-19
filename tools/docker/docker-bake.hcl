group "build-all" {
    targets = ["certbot", 
    "dns-dnsmadeeasy",
    "dns-dnsimple",
    "dns-ovh",
    "dns-cloudflare",
    "dns-digitalocean",
    "dns-google",
    "dns-luadns",
    "dns-nsone",
    "dns-rfc2136",
    "dns-route53",
    "dns-gehirn",
    "dns-linode",
    "dns-sakuracloud"]
    
}

variable "WORK_DIR" {
    default = "tools/docker"
}

variable "TAG_VER" {
    default = "test"
}

variable "TAG_ARCH" {
    default = "auto"
}

variable "REGISTRY_SPEC" {
    // if provided, this should include the trailing slash (e.g. "certbot/)
    default = ""
}

target "certbot" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot"
    tags = ["${REGISTRY_SPEC}certbot:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-dnsmadeeasy" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-dnsmadeeasy"}
    tags = ["${REGISTRY_SPEC}dns-dnsmadeeasy:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-dnsimple" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-dnsimple"}
    tags = ["${REGISTRY_SPEC}dns-dnsimple:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-ovh" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-ovh"}
    tags = ["${REGISTRY_SPEC}dns-ovh:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-cloudflare" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-cloudflare"}
    tags = ["${REGISTRY_SPEC}dns-cloudflare:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-digitalocean" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-digitalocean"}
    tags = ["${REGISTRY_SPEC}dns-digitalocean:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-google" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-google"}
    tags = ["${REGISTRY_SPEC}dns-google:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-luadns" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-luadns"}
    tags = ["${REGISTRY_SPEC}dns-luadns:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-nsone" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-nsone"}
    tags = ["${REGISTRY_SPEC}dns-nsone:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-rfc2136" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-rfc2136"}
    tags = ["${REGISTRY_SPEC}dns-rfc2136:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-route53" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-route53"}
    tags = ["${REGISTRY_SPEC}dns-route53:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-gehirn" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-gehirn"}
    tags = ["${REGISTRY_SPEC}dns-gehirn:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-linode" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-linode"}
    tags = ["${REGISTRY_SPEC}dns-linode:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

target "dns-sakuracloud" {
    dockerfile = "${WORK_DIR}/Dockerfile"
    target = "certbot-plugin"
    contexts = {plugin-src = "certbot-dns-sakuracloud"}
    tags = ["${REGISTRY_SPEC}dns-sakuracloud:${TAG_ARCH}-${TAG_VER}"]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v6"]
}

