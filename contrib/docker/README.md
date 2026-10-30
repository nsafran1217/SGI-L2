# l2 in Docker

The image runs `l2` with its console on telnet, like
[SGI-L2-Docker](https://github.com/nsafran1217/SGI-L2-Docker) did with
SGI's original binaries, but needs nothing on the host: no `sgil1`
kernel driver, no 32-bit libraries. It is built for x86-64 (`amd64`),
64-bit ARM (`arm64`: a Raspberry Pi 3, 4 or 5 on a 64-bit OS) and 32-bit
ARM (`arm/v7`: a Pi 2 or later on 32-bit Raspberry Pi OS; not the Pi 1 or
Zero).

One container runs:

| | |
|---|---|
| `l2` | the L2, with the L1s on the host's USB; its settings (`l2.conf`) and log are in the volume `l2-state` |
| telnet | the L2's console on telnet port 23, with no login: `telnet <host>`, CTRL-] then `q` to leave |
| `l2api` | (with `WEBGUI=1`) the web l2gui and the HTTP API on port 8080 |

It is on the host's network, so `l2` is reached as if it ran on the host:
SGI's `l2term`, `l2cmd`, `l2gui` and IST tools with `--l2 <host>` (ports
8000-8003, 9002), other L2s (9001), discovery (UDP 10000), and the console
on `telnet <host> 8001` too.

## Quick Setup

This will setup the docker container with l2 running telnet on port 23 and the web gui on 8080.

Download the `docker-compose.yml` and bring it up: 

    mkdir sgi-l2 && cd sgi-l2
    curl -LO https://raw.githubusercontent.com/nsafran1217/SGI-L2/main/contrib/docker/docker-compose.yml
    docker compose up -d                      # pulls ghcr.io/nsafran1217/sgi-l2
    # Connect to l2:
    telnet localhost

Settings are under `environment:` in `docker-compose.yml`; edit them
there, then `docker compose up -d` again:

| | |
|---|---|
| `WEBGUI=1` | Enabled the web l2gui, at http://\<host\>:8080/ |
| `WEBGUI_LISTEN` | where it listens (default `0.0.0.0:8080`) |
| `L2_OPTIONS` | `l2`'s options (default `-discover`) |
| `TELNET_PORT` | the l2 console's telnet port |


Then:

    docker compose logs -f                    # l2's messages
    docker compose pull && docker compose up -d     # a new release

`quit` on the console ends `l2`, and with it the container (dropping any
other telnet sessions); Docker starts it again.

## Separate containers
If you for example only want to run the webgui with a real L2, you can run each part separately.
See this example `docker-compose.yml` file:

    services:
      # l2: Connects to the L1s on USB, its settings and log in the volume
      l2:
        image: ghcr.io/nsafran1217/sgi-l2:latest
        container_name: sgi-l2
        command: ["l2"]
        network_mode: host
        restart: always
        environment:
          L2_OPTIONS: "-discover"
        device_cgroup_rules:
          - 'c 189:* rmw'
        volumes:
          - /dev/bus/usb:/dev/bus/usb
          - l2-state:/var/lib/sgi-l2

      # the console of the l2 above on telnet (any L2's console is also on
      # telnet <host> 8001)
      telnet:
        image: ghcr.io/nsafran1217/sgi-l2:latest
        container_name: sgi-l2-telnet
        command: ["telnet"]
        network_mode: host
        restart: always
        environment:
          TELNET_PORT: "23"

      # the web l2gui, for the l2 above. For another L2 (a hardware one, or
      # one on another host), add its address: ["webgui", "--l2", "<host>"]
      webgui:
        image: ghcr.io/nsafran1217/sgi-l2:latest
        container_name: sgi-l2-webgui
        command: ["webgui"]
        network_mode: host
        restart: always
        environment:
          WEBGUI_LISTEN: "0.0.0.0:8080"

    volumes:
      l2-state:

Leave out the services you don't need: for only the web l2gui with a
real L2, keep `webgui` alone, with that L2's address after `--l2`.

## Without compose

    docker run -d --name sgi-l2 --network host --restart always \
        --device-cgroup-rule 'c 189:* rmw' -v /dev/bus/usb:/dev/bus/usb \
        -v l2-state:/var/lib/sgi-l2 \
        -e WEBGUI=1 ghcr.io/nsafran1217/sgi-l2

`l2`'s options can follow as arguments (`... ghcr.io/nsafran1217/sgi-l2
all -noconn`). The image also runs each part alone, for one container
each: `l2 [options]`, `telnet` and `webgui` in place of `all`.


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

## USB

`l2` opens the L1s (USB `065e:1234`) through libusb. The container sees
the host's `/dev/bus/usb`, and the device cgroup rule lets it open USB
devices plugged in after it started. libusb learns of them from the
kernel's hotplug events (the image's libusb has no udev), which reach a
container only on the host's network: one more reason for host
networking. `l2` runs as root in the container, so the host needs no
udev rule.

In a VM (Proxmox and the like), pass the L1 through to the VM first, by
its vendor and device ID, `065e:1234`. Behind a router brick, which acts as
a USB hub, pass the whole USB controller through instead (a PCIe USB card
is the simple way).

## Security

There is none.  
Neither telnet nor the web l2gui asks for a password: whoever reaches
port 23 or 8080 can power the system up and down. Run it on a network you
trust. For the web l2gui from elsewhere, set `WEBGUI_LISTEN=127.0.0.1:8080`
and put a reverse proxy with TLS and a password in front of it (see the
README's `l2api` section).
