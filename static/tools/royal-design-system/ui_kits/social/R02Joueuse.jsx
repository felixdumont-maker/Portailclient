/* global React */
/**
 * R02 — JOUEUSE
 * Photo à gauche en background-image pour éviter la déformation à l’export PNG.
 * Bloc d’informations à droite, centré dans la colonne, mais texte aligné à gauche.
 * Logos partenaires sous les stats.
 */
function R02Joueuse({ data = R02Joueuse.defaults }) {
  const stats = data.stats || [];
  const sponsors = data.sponsors || [];
  const photoPosition = data.photoPosition || 'center top';
  const colors = data.colors || {};
  const colorVars = {};
  if (colors.bg)     colorVars['--template-bg'] = colors.bg;
  if (colors.pillBg) colorVars['--pill-bg']      = colors.pillBg;
  if (colors.pillFg) colorVars['--pill-fg']      = colors.pillFg;

  return (
    <div className="stage-1080" id="R02" style={colorVars}>
      {/* PHOTO LEFT PANEL */}
      <div
        style={{
          position: 'absolute',
          left: 20,
          top: 20,
          width: 520,
          height: 1040,
          overflow: 'hidden',
          backgroundColor: '#2a2a2a',
          backgroundImage: data.photo ? `url("${data.photo}")` : 'none',
          backgroundSize: 'cover',
          backgroundPosition: photoPosition,
          backgroundRepeat: 'no-repeat'
        }}
      >
        {!data.photo && (
          <div
            style={{
              width: '100%',
              height: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--surface-mid)',
              color: 'var(--fg-tertiary)',
              fontFamily: 'var(--font-display)',
              fontSize: 34,
              letterSpacing: '0.08em',
              textAlign: 'center'
            }}
          >
            PHOTO
            <br />
            JOUEUSE
          </div>
        )}

        <div
          style={{
            position: 'absolute',
            inset: 0,
            background:
              'linear-gradient(180deg, rgba(0,0,0,0.02) 0%, rgba(0,0,0,0.18) 100%)',
            pointerEvents: 'none'
          }}
        />
      </div>

      {/* RIGHT PANEL */}
      <div
        style={{
          position: 'absolute',
          right: 20,
          top: 20,
          width: 520,
          height: 1040,
          padding: '64px 42px 42px 42px',
          boxSizing: 'border-box',
          display: 'flex',
          flexDirection: 'column',
          background:
            'linear-gradient(180deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%)'
        }}
      >
        {/* Bloc centré dans la colonne, mais aligné à gauche */}
        <div
          style={{
            width: 410,
            margin: '0 auto',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-start',
            textAlign: 'left'
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: '0.22em',
              color: 'var(--fg-muted)',
              textTransform: 'uppercase',
              marginBottom: 18,
              width: '100%'
            }}
          >
            {data.eyebrow}
          </div>

          <div
            style={{
              fontSize: 18,
              fontWeight: 700,
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: 'var(--fg-primary)',
              marginBottom: 12,
              width: '100%'
            }}
          >
            {data.position}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 118,
              lineHeight: 0.88,
              letterSpacing: '-0.03em',
              textShadow: 'var(--shadow-press)',
              marginBottom: 10,
              width: '100%'
            }}
          >
            #{data.number}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 56,
              lineHeight: 0.9,
              letterSpacing: '0.02em',
              textTransform: 'uppercase',
              textShadow: 'var(--shadow-press)',
              width: '100%'
            }}
          >
            {data.firstName}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 72,
              lineHeight: 0.88,
              letterSpacing: '0.02em',
              textTransform: 'uppercase',
              color: 'var(--fg-tertiary)',
              textShadow: 'var(--shadow-press)',
              marginBottom: 14,
              width: '100%'
            }}
          >
            {data.lastName}
          </div>

          <div
            style={{
              fontSize: 16,
              fontWeight: 700,
              letterSpacing: '0.14em',
              textTransform: 'uppercase',
              color: 'var(--fg-primary)',
              marginBottom: 16,
              width: '100%'
            }}
          >
            {data.shoots}
          </div>

          <div
            style={{
              width: '100%',
              paddingTop: 18,
              borderTop: '2px solid rgba(255,255,255,0.18)',
              marginTop: 2
            }}
          >
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: '0.2em',
                color: 'var(--fg-muted)',
                textTransform: 'uppercase',
                marginBottom: 8
              }}
            >
              {data.bioTitle || 'BIO'}
            </div>

            <div
              style={{
                fontSize: 15,
                lineHeight: 1.55,
                color: 'var(--fg-secondary)',
                minHeight: 96
              }}
            >
              {data.bio}
            </div>
          </div>

          <div
            style={{
              marginTop: 24,
              width: '100%',
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 12
            }}
          >
            {stats.map((stat, index) => (
              <div
                key={index}
                style={{
                  background: 'rgba(0,0,0,0.16)',
                  border: '1px solid rgba(255,255,255,0.10)',
                  borderRadius: '12px',
                  padding: '14px 10px',
                  textAlign: 'center'
                }}
              >
                <div
                  style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 42,
                    lineHeight: 1
                  }}
                >
                  {stat.value}
                </div>

                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: '0.20em',
                    color: 'var(--fg-muted)',
                    textTransform: 'uppercase',
                    marginTop: 6
                  }}
                >
                  {stat.label}
                </div>
              </div>
            ))}
          </div>

          {/* LOGOS SOUS LES STATS */}
          <div
            style={{
              marginTop: 24,
              width: '100%',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'flex-start',
              gap: 10
            }}
          >
            <div
              style={{
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: '0.18em',
                color: 'var(--fg-muted)',
                textTransform: 'uppercase'
              }}
            >
              {data.sponsorsTitle || 'PARTENAIRES'}
            </div>

            <div
              style={{
                width: '100%',
                minHeight: 42,
                display: 'flex',
                flexWrap: 'wrap',
                justifyContent: 'flex-start',
                alignItems: 'center',
                gap: 16
              }}
            >
              {sponsors.map((sponsor, index) => (
                sponsor.logo ? (
                  <img
                    key={index}
                    src={sponsor.logo}
                    alt={sponsor.name}
                    style={{
                      maxHeight: 38,
                      maxWidth: 96,
                      objectFit: 'contain',
                      opacity: 0.95,
                      display: 'block'
                    }}
                  />
                ) : (
                  <div
                    key={index}
                    className="logo-box"
                    style={{ width: 80, height: 38, borderRadius: 6 }}
                  >
                    <span className="ph">{sponsor.name || 'LOGO'}</span>
                  </div>
                )
              ))}
            </div>
          </div>
        </div>

        <div style={{ flex: 1 }} />

        <div
          className="kit-footer"
          style={{
            marginTop: 24,
            width: '100%'
          }}
        >
          <span className="kit-footer-left">
            {data.footerLeft || 'JOUEUSE EN VEDETTE'}
          </span>

          <span className="kit-footer-right">
            {data.footerRight || 'COCKTAIL MÉDIA'}
          </span>
        </div>
      </div>
    </div>
  );
}

R02Joueuse.defaults = {
  colors: {},
  eyebrow: 'LNHBF · SAISON 2026 · ROYAL DE SHAWINIGAN',
  number: '91',
  position: 'DÉFENSEURE',
  shoots: 'LANCER GAUCHE',
  firstName: 'CAMILLE',
  lastName: 'LAVOIE',
  bioTitle: 'BIO',
  bio: 'Capitaine du Royal depuis 2023, Charlotte mène l’équipe à coups de présence physique et de tirs précis dans la lucarne.',
  photo: '../../assets/photo-joueuse-placeholder.svg',
  photoPosition: 'center top',
  footerLeft: 'JOUEUSE EN VEDETTE',
  footerRight: 'COCKTAIL MÉDIA',

  sponsorsTitle: 'PARTENAIRES',
  sponsors: [
    {
      name: 'LNHBF',
      logo: '../../assets/logo-lnhbf-white.png'

    },
    {
      name: 'LPS Physiothérapie',
      logo: '../../assets/logos/sponsors/lps-blanc.png'
    },
    {
      name: 'Royal',
      logo: '../../assets/logos/royal-shawinigan.png'

    },
    {
      name: 'Royal LePage Centre',
      logo: '../../assets/logos/sponsors/royal-lepage-centre.png'
    }
  ],

  stats: [
    {
      label: 'MATCHS',
      value: '12'
    },
    {
      label: 'BUTS',
      value: '9'
    },
    {
      label: 'AIDES',
      value: '14'
    },
    {
      label: 'POINTS',
      value: '23'
    }
  ]
};

window.R02Joueuse = R02Joueuse;
