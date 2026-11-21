// Tema, ilk boyamadan once uygulanir. Content-Security-Policy satir ici betige izin
// vermedigi icin ayri dosyadadir.
(function () {
  try {
    var raw = localStorage.getItem('mihenk.theme');
    var pref = raw ? JSON.parse(raw) : 'system';
    var dark = pref === 'dark' || (pref !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  } catch (e) {}
})();
