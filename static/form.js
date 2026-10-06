(function () {
  var c = document.getElementById('obs_ativa'), t = document.getElementById('observacoes');
  if (!c || !t) return;
  c.addEventListener('change', function () {
    t.disabled = !c.checked;
    if (c.checked) t.focus();
  });
})();
