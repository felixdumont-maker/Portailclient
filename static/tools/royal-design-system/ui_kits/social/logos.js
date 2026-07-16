/* global window */
/**
 * Shared logo registry for the Royal social UI kit.
 * All paths are relative to ui_kits/social/index.html.
 */
const ROYAL_ASSETS = {
  // Royal de Shawinigan — primary mark (full color)
  royal:        '../../assets/logos/royal-shawinigan.svg',
  // Generated white knockout fallback (kept from earlier scaffold)
  royalWhite:   '../../assets/logo-royal-white.svg',
  // LNHBF league mark (white knockout)
  lnhbf:        '../../assets/logos/lnhbf-league-white.png',
  // Cocktail Média credit lockups
  cocktailIcon:        '../../assets/logos/cocktail-media-icon.png',
  cocktailIconWhite:   '../../assets/logos/cocktail-media-icon-white.png',
  cocktailStacked:     '../../assets/logos/cocktail-media-stacked-black.png',
  cocktailWordmark:    '../../assets/logos/cocktail-media-wordmark-long.jpg',
  // LNHBF opponent teams (filename keys → asset path)
  teams: {
    anjou:      '../../assets/logos/teams/anjou.png',
    granby:     '../../assets/logos/teams/granby.png',
    joliette:   '../../assets/logos/teams/joliette.png',
    levis:      '../../assets/logos/teams/levis.png',
    montreal:   '../../assets/logos/teams/montreal.png',
    sherbrooke: '../../assets/logos/teams/sherbrooke.png',
    sthubert:   '../../assets/logos/teams/sthubert.png',
    mirabel:    '../../assets/logos/teams/mirabel.png'
  },
  // Sponsors (presentation-only)
  sponsors: {
    royalLepage: '../../assets/logos/sponsors/royal-lepage-centre.png',
    lps:         '../../assets/logos/sponsors/lps-blanc.png'
  }
};

window.ROYAL_ASSETS = ROYAL_ASSETS;
