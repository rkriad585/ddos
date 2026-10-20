(function () {
  "use strict";

  var logo = document.getElementById("ddos-home-logo");
  if (!logo) return;

  function updateLogo() {
    var scheme = document.documentElement.getAttribute("data-md-color-scheme");
    var dark = scheme === "slate" || scheme === "dark";
    var next = dark ? logo.dataset.logoDark : logo.dataset.logoLight;
    if (next && logo.getAttribute("src") !== next) {
      logo.setAttribute("src", next);
    }
  }

  updateLogo();

  new MutationObserver(updateLogo).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["data-md-color-scheme"],
  });
})();
