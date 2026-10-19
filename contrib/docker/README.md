# l2 in a container

The kernel driver is gone, so a container needs nothing on the host but the
USB device nodes. A minimal image (Debian 13):

    FROM debian:trixie-slim
    RUN apt-get update && apt-get install -y --no-install-recommends libusb-1.0-0 \
        && rm -rf /var/lib/apt/lists/*
    COPY l2 l2term l2cmd /usr/local/bin/
    WORKDIR /var/lib/sgi-l2
    VOLUME /var/lib/sgi-l2
    ENTRYPOINT ["/usr/local/bin/l2"]
    CMD ["-discover"]

with `l2`, `l2term` and `l2cmd` from `make` next to it. Run it with the
host's USB devices and network (discovery is UDP broadcast, and other L2s
connect back):

    docker run -d --name l2 --network host --device /dev/bus/usb \
        -v l2-state:/var/lib/sgi-l2 sgi-l2

`--device /dev/bus/usb` gives the container the devices present when it
starts; for L1s plugged in later, add the device cgroup rule
`--device-cgroup-rule 'c 189:* rmw'` and bind-mount `/dev/bus/usb`, or
restart the container. In a VM, pass the L1s (or, behind a router brick,
the whole USB controller) through to the VM first.

Consoles: `docker exec -it l2 l2term --l2 localhost`, or `telnet <host> 8001`.
