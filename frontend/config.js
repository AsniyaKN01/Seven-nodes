(function () {
  var scripts = document.getElementsByTagName("script");
  var base = "http://127.0.0.1:8000";
  for (var i = 0; i < scripts.length; i++) {
    var attr = scripts[i].getAttribute("data-api-base");
    if (attr) {
      base = attr;
      break;
    }
  }
  window.API_BASE = base.replace(/\/$/, "");
})();
