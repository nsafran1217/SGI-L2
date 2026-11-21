/* The panel's size: the largest whole multiple of 320x240 device pixels
 * that fits the window below the L2 bar, or ?scale=N */
(function () {
  const screen = document.getElementById("screen");
  const bar = document.getElementById("l2bar");
  const fixed = parseInt(new URLSearchParams(location.search).get("scale"), 10);

  function fit() {
    const dpr = window.devicePixelRatio || 1;
    const h = innerHeight - (bar ? bar.offsetHeight : 0);
    const n = fixed > 0 ? fixed * dpr :
      Math.max(1, Math.min(Math.floor(innerWidth * dpr / 320), Math.floor(h * dpr / 240)));
    screen.style.width = 320 * n / dpr + "px";
    screen.style.height = 240 * n / dpr + "px";
  }
  addEventListener("resize", fit);
  fit();
})();
