// Theme bootstrap: apply the saved theme before the app module renders, so a
// light-theme user never sees a dark flash. Loaded as a classic (non-module)
// script in <head> so it runs synchronously ahead of the app bundle; kept as a
// file rather than an inline <script> so the CSP can keep `script-src 'self'`.
try {
  var savedTheme = localStorage.getItem('kerennnn-theme');
  if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;
} catch (_) {}
