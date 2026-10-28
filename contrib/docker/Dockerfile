# syntax=docker/dockerfile:1
#
# The SGI L2 (l2, l2term, l2cmd, l2api and the web l2gui) for linux/amd64,
# linux/arm64 and linux/arm/v7, built from this checkout: the build context
# is the repository's root. Targets:
#
#   runtime (the default)  the image docker-compose.yml runs (README.md)
#   dist                   the release archive (make dist), with l2gui as well:
#                          docker buildx build -f contrib/docker/Dockerfile --target dist -o dist .
#
# .github/workflows/release.yml builds both for each release. The tools are
# static, built with musl (Alpine), so the archive runs on any Linux. Only
# dist builds FLTK (for l2gui), so building the image builds no FLTK.

FROM alpine:3.22 AS build
# (GNU tar: make dist gives the files to root)
RUN apk add --no-cache build-base linux-headers pkgconf libusb-dev tar
WORKDIR /src
COPY . .
ARG VERSION=dev
# (set by BuildKit: amd64, arm64, arm with v7)
ARG TARGETARCH
ARG TARGETVARIANT
# (WERROR=: a release isn't held up by a new compiler's warnings)
RUN make -j"$(nproc)" dist STATIC=yes VERSION="$VERSION" DIST_ARCH="$TARGETARCH$TARGETVARIANT" WERROR= \
 && mkdir /stage \
 && tar -xzf build/dist/sgi-l2-*.tar.gz -C /stage --strip-components=1

# FLTK for l2gui: 1.3.8, the release tests/l2gui_test.py compares with
# SGI's l2gui, built as ../retools/setup_fltk.sh builds its 32-bit FLTK
# (core X fonts; no Xft, XRender, XFixes or OpenGL). And libXau, which
# Alpine has no static library of (libxcb needs it).
FROM alpine:3.22 AS fltk
RUN apk add --no-cache build-base cmake xz libx11-dev libxext-dev xorgproto
ADD --checksum=sha256:74d0e4dfa3d39ad8939e99bda37f5967aba528211076828464d2777d477fc0fb \
    https://www.x.org/releases/individual/lib/libXau-1.0.12.tar.xz /tmp/libXau.tar.xz
ADD --checksum=sha256:f3c1102b07eb0e7a50538f9fc9037c18387165bc70d4b626e94ab725b9d4d1bf \
    https://www.fltk.org/pub/fltk/1.3.8/fltk-1.3.8-source.tar.gz /tmp/fltk.tar.gz
RUN tar -xJf /tmp/libXau.tar.xz -C /tmp \
 && cd /tmp/libXau-1.0.12 \
 && ./configure --prefix=/opt/xau --enable-static --disable-shared \
 && make -j"$(nproc)" install \
 && rm -rf /tmp/libXau*
RUN tar -xzf /tmp/fltk.tar.gz -C /tmp \
 && cmake -S /tmp/fltk-1.3.8 -B /tmp/fltk-build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/fltk \
        -DFLTK_BUILD_TEST=OFF -DOPTION_USE_GL=OFF -DOPTION_USE_XFT=OFF \
        -DOPTION_USE_XINERAMA=OFF -DOPTION_USE_XCURSOR=OFF -DOPTION_USE_SVG=OFF \
        -DOPTION_USE_XRENDER=OFF -DOPTION_USE_XFIXES=OFF -DOPTION_USE_XDBE=OFF \
        -DOPTION_USE_SYSTEM_LIBJPEG=OFF -DOPTION_USE_SYSTEM_LIBPNG=OFF -DOPTION_USE_SYSTEM_ZLIB=OFF \
        -DOPTION_BUILD_HTML_DOCUMENTATION=OFF -DOPTION_BUILD_PDF_DOCUMENTATION=OFF \
 && cmake --build /tmp/fltk-build -j"$(nproc)" \
 && cmake --install /tmp/fltk-build \
 && rm -rf /tmp/fltk*

# the archive: the build above, and l2gui (only it is compiled again),
# static with X11 too
FROM build AS build-dist
ARG VERSION=dev
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache libx11-dev libx11-static libxcb-static libxext-dev libxext-static libxau-dev libxdmcp-dev
COPY --from=fltk /opt/fltk /opt/fltk
COPY --from=fltk /opt/xau/lib/libXau.a /usr/lib/
RUN make -j"$(nproc)" dist STATIC=yes VERSION="$VERSION" DIST_ARCH="$TARGETARCH$TARGETVARIANT" WERROR= \
        FLTK_CONFIG=/opt/fltk/bin/fltk-config \
 && tar -tzf build/dist/sgi-l2-*.tar.gz | grep -q /bin/l2gui$

FROM scratch AS dist
COPY --from=build-dist /src/build/dist/*.tar.gz /

# (busybox-extras: telnetd)
FROM alpine:3.22 AS runtime
RUN apk add --no-cache tini setpriv busybox-extras
# the tools (static: no libusb to install) into /usr/local/bin, the web l2gui
# into /usr/local/share/sgi-l2/www
RUN --mount=type=bind,from=build,source=/stage,target=/tmp/sgi-l2 /tmp/sgi-l2/install.sh --tools-only
COPY --chmod=755 contrib/docker/entrypoint.sh /usr/local/bin/sgi-l2-entry
COPY --chmod=755 contrib/docker/l2-console /usr/local/sbin/l2-console
WORKDIR /var/lib/sgi-l2
VOLUME /var/lib/sgi-l2
# telnet; L3 tools (8000, 8002); the SMP consoles (8001, 8003); other L2s
# (9001); L2 applications such as l2gui (9002); discovery; the web l2gui
EXPOSE 23 8000 8001 8002 8003 9001 9002 10000/udp 8080
# (-g: docker stop's SIGTERM to the whole process group)
ENTRYPOINT ["/sbin/tini", "-g", "--", "/usr/local/bin/sgi-l2-entry"]
CMD ["all"]
