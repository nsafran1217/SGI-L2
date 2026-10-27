# l2 in Docker

The image runs `l2` with its console on telnet, like
[SGI-L2-Docker](https://github.com/nsafran1217/SGI-L2-Docker) did with
SGI's original binaries, but needs nothing on the host: no `sgil1`
kernel driver, no 32-bit libraries. It is built for x86-64 (`amd64`),
64-bit ARM (`arm64`: a Raspberry Pi 3, 4 or 5 on a 64-bit OS) and 32-bit
ARM (`arm/v7`: a Pi 2 or later on 32-bit Raspberry Pi OS; not the Pi 1 or
Zero).

`docker-compose.yml` runs three containers from the same image:

| | |
|---|---|
| `l2` | the L2, with the L1s on the host's USB; its settings (`l2.conf`) and log are in the volume `l2-state` |
| `telnet` | the L2's console on telnet port 23, with no login: `telnet <host>`, CTRL-] then `q` to leave |
| `webgui` | (only with the profile `webgui`) the web l2gui and the HTTP API, `l2api`, on port 8080 |

All three are on the host's network, so `l2` is reached as if it ran on
the host: SGI's `l2term`, `l2cmd`, `l2gui` and IST tools with `--l2 <host>`
(ports 8000-8003, 9002), other L2s (9001), discovery (UDP 10000), and the
console on `telnet <host> 8001` too.

## Run

    git clone https://github.com/nsafran1217/SGI-L2.git
    cd SGI-L2/contrib/docker
    docker compose up -d                      # pulls ghcr.io/nsafran1217/sgi-l2
    telnet localhost

With the web l2gui (http://\<host\>:8080/):

    docker compose --profile webgui up -d

or `COMPOSE_PROFILES=webgui` in `.env`. Settings go in `.env` next to
`docker-compose.yml` (`.env.example` lists them): `l2`'s options
(`L2_OPTIONS`, default `-discover`), the telnet port (`TELNET_PORT`, if the
host has a telnetd on 23), where the web l2gui listens (`WEBGUI_LISTEN`),
the image's tag (`SGI_L2_TAG`, a release such as `1.0.0`, default `latest`).

    docker compose logs -f l2                 # l2's messages
    docker compose exec l2 l2cmd --l2 localhost cfg
    docker compose pull && docker compose up -d     # a new release

`quit` on the console ends `l2`; Docker starts it again.

## Build it yourself

From a checkout, instead of pulling the image:

    docker compose build

The build compiles the tools in an Alpine container, for the machine it
runs on (a Raspberry Pi 2 takes about 15 minutes). For another architecture, with
`docker buildx` and QEMU, from the repository's root:

    docker buildx build --platform linux/arm/v7 -f contrib/docker/Dockerfile -t sgi-l2 --load .

`--target dist -o dist` instead makes the release archive (`make dist`)
for each `--platform`, to install without Docker; see
`contrib/dist/INSTALL.md`. The archive has `l2gui` as well, so this
target also builds FLTK, which the image doesn't need.

## Without compose

    docker volume create l2-state
    docker run -d --name l2 --network host --restart always \
        --device-cgroup-rule 'c 189:* rmw' -v /dev/bus/usb:/dev/bus/usb \
        -v /run/udev:/run/udev:ro -v l2-state:/var/lib/sgi-l2 \
        ghcr.io/nsafran1217/sgi-l2 l2 -discover
    docker run -d --name l2-telnet --network host --restart always \
        ghcr.io/nsafran1217/sgi-l2 telnet
    docker run -d --name l2-webgui --network host --restart always \
        ghcr.io/nsafran1217/sgi-l2 webgui

## USB

`l2` opens the L1s (USB `065e:1234`) through libusb. The container sees
the host's `/dev/bus/usb`, and the device cgroup rule lets it open USB
devices plugged in after it started; `/run/udev` gives libusb the host's
hotplug events. `l2` runs as root in its container, so the host needs no
udev rule.

In a VM (Proxmox and the like), pass the L1 through to the VM first, by
its vendor and device ID, `065e:1234`. Behind a router brick, which acts as
a USB hub, pass the whole USB controller through instead (a PCIe USB card
is the simple way).

## Security

Neither telnet nor the web l2gui asks for a password: whoever reaches
port 23 or 8080 can power the system up and down. Run it on a network you
trust. For the web l2gui from elsewhere, set `WEBGUI_LISTEN=127.0.0.1:8080`
and put a reverse proxy with TLS and a password in front of it (see the
README's `l2api` section).
