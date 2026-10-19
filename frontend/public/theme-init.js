// Applied before first paint to avoid a light/dark flash. Kept external for the strict CSP.
(function () {
  try {
    var pref = localStorage.getItem("tim-theme") || "dark";
    var dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  } catch (e) {}
})();
