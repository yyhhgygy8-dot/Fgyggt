(function () {
  var b = document.getElementById('copybtn'), p = document.getElementById('conf');
  if (!b || !p) return;
  b.addEventListener('click', function () {
    var t = p.textContent;
    function done() { b.textContent = 'کپی شد ✓'; setTimeout(function () { b.textContent = 'کپی کانفیگ'; }, 2000); }
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(t).then(done); return; }
    var ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) {}
    ta.remove();
  });
})();
