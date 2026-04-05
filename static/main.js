/* =========================================================
   COCKTAIL MÉDIA — PORTAIL CLIENT
   main.js — Comportements progressifs
   ========================================================= */

/* =========================
   1) FLASH MESSAGES
   Disparaissent automatiquement après 4 secondes
   ========================= */
(function () {
  const flashes = document.querySelectorAll('.flash');

  flashes.forEach(function (flash) {
    // Disparition après 4 secondes
    setTimeout(function () {
      flash.style.transition = 'opacity 0.5s ease';
      flash.style.opacity = '0';

      // Retire l'élément du DOM après la transition
      setTimeout(function () {
        flash.remove();
      }, 500);
    }, 4000);
  });
})();


/* =========================
   2) CONFIRMATIONS DE SUPPRESSION
   Remplace les onclick="return confirm(...)" par
   un vrai dialog natif plus accessible
   ========================= */
(function () {
  // On cible tous les liens de suppression
  const deleteLinks = document.querySelectorAll('.btn-delete');

  deleteLinks.forEach(function (link) {
    // On retire le confirm inline s'il existe
    link.removeAttribute('onclick');

    link.addEventListener('click', function (e) {
      e.preventDefault();

      const destination = link.href;
      const confirmed = window.confirm('Êtes-vous sûr de vouloir supprimer cet élément ? Cette action est irréversible.');

      if (confirmed) {
        window.location.href = destination;
      }
    });
  });
})();


/* =========================
   3) NAV ACTIVE
   Ajoute la classe "is-active" sur le lien
   de navigation qui correspond à l'URL courante
   ========================= */
(function () {
  const navLinks = document.querySelectorAll('.nav-link');
  const currentPath = window.location.pathname;

  navLinks.forEach(function (link) {
    // Comparaison simple sur le pathname
    if (link.getAttribute('href') === currentPath) {
      link.classList.add('is-active');
    }
  });
})();


/* =========================
   4) CHECKLIST — FEEDBACK VISUEL IMMÉDIAT
   Quand on clique sur un item de checklist,
   on bascule la classe "completed" localement
   avant que le serveur réponde (évite le flash blanc)
   ========================= */
(function () {
  const checklistItems = document.querySelectorAll('.checklist-item');

  checklistItems.forEach(function (item) {
    const link = item.querySelector('.item-link');
    if (!link) return;

    link.addEventListener('click', function () {
      // Toggle visuel immédiat
      item.classList.toggle('completed');
    });
  });
})();
