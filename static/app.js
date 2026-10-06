// Confirmação antes de enviar formulários com data-confirm (compatível com a CSP: sem JS inline)
document.addEventListener('submit', function (e) {
  var msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});
