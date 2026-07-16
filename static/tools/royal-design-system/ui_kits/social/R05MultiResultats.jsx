/* global React */
/**
 * R05 — RÉSULTATS (multi-match recap)
 * Two stacked match-result cards on a single 1080×1080.
 * Each card: outcome chip, teams + scores, brief scorer line.
 */
function R05MultiResultats({ data = R05MultiResultats.defaults }) {
  const colors = data.colors || {};
  const colorVars = {};
  if (colors.bg)     colorVars['--template-bg'] = colors.bg;
  if (colors.pillBg) colorVars['--pill-bg']      = colors.pillBg;
  if (colors.pillFg) colorVars['--pill-fg']      = colors.pillFg;
  return (
    <div className="stage-1080" id="R05" style={colorVars}>
      <div style={{position:'absolute', inset:0, padding:'72px 80px', display:'flex', flexDirection:'column', gap:22}}>
        <div style={{display:'flex', flexDirection:'column', gap:12}}>
          <div className="kit-eyebrow">{data.eyebrow}</div>
          <div style={{
            fontFamily:'var(--font-display)', fontSize:96, lineHeight:0.86,
            letterSpacing:'var(--ls-display)', textShadow:'var(--shadow-press)',
            textTransform:'uppercase'
          }}>RÉSULTATS<br/>DE LA SOIRÉE</div>
          <div style={{fontSize:14, fontWeight:700, letterSpacing:'0.18em', color:'var(--fg-tertiary)'}}>{data.date}</div>
        </div>

        <div style={{flex:1, display:'flex', flexDirection:'column', gap:18}}>
          {data.matches.map((m, i) => <ResultRow key={i} m={m}/>)}
        </div>

        <div className="kit-footer">
          <span className="kit-footer-left">NOS PARTENAIRES</span>
          <span className="kit-footer-right">COCKTAIL MÉDIA</span>
        </div>
      </div>
    </div>
  );
}

function ResultRow({ m }) {
  const win = m.outcome === 'VICTOIRE';
  return (
    <div style={{
      background:'var(--surface-deep)', border:'1px solid var(--border-soft)',
      borderRadius:'var(--r-card)', padding:'24px 28px',
      display:'grid', gridTemplateColumns:'auto 1fr auto', gap:24,
      alignItems:'center', position:'relative', overflow:'hidden'
    }}>
      <div style={{
        position:'absolute', left:0, top:0, bottom:0, width:6,
        background: win ? 'var(--win-fg)' : 'var(--loss-fg)'
      }}/>
      <span style={{
        fontFamily:'var(--font-display)', fontSize:18, letterSpacing:'0.12em',
        background: win ? 'var(--win-bg)' : 'var(--loss-bg)',
        color: win ? 'var(--win-fg)' : 'var(--loss-fg)',
        padding:'8px 18px', borderRadius:'var(--r-pill)'
      }}>{m.outcome}</span>

      <div style={{display:'flex', alignItems:'center', gap:24}}>
        <TeamScore name={m.home} score={m.homeScore} winner={win}  logo={m.homeLogo}/>
        <div style={{fontFamily:'var(--font-display)', fontSize:24, color:'var(--fg-muted)'}}>—</div>
        <TeamScore name={m.away} score={m.awayScore} winner={!win} logo={m.awayLogo}/>
      </div>

      <div style={{textAlign:'right', maxWidth:300}}>
        <div style={{fontSize:11, fontWeight:700, letterSpacing:'0.22em', color:'var(--fg-muted)'}}>BUTEUSES ROYAL</div>
        <div style={{fontSize:14, marginTop:6, lineHeight:1.4, color:'var(--fg-secondary)'}}>{m.scorers}</div>
      </div>
    </div>
  );
}

function TeamScore({ name, score, winner, logo }) {
  return (
    <div style={{display:'flex', alignItems:'center', gap:14}}>
      <div className="logo-box" style={{width:64, height:64, borderRadius:10}}>
        {logo
          ? <img src={logo} alt="" style={{width:'80%',height:'80%'}}/>
          : <span className="ph" style={{fontSize:7}}>{name}</span>}
      </div>
      <div>
        <div style={{fontFamily:'var(--font-display)', fontSize:24, lineHeight:1, letterSpacing:'0.04em'}}>{name}</div>
        <div style={{
          fontFamily:'var(--font-display)', fontSize: winner ? 64 : 48,
          lineHeight:0.95, color: winner ? 'var(--fg-primary)' : 'var(--fg-tertiary)',
          textShadow: winner ? 'var(--shadow-press)' : 'none'
        }}>{score}</div>
      </div>
    </div>
  );
}

R05MultiResultats.defaults = {
  colors: {},
  eyebrow: 'ROYAL DE SHAWINIGAN · LNHBF',
  date: 'SAMEDI 18 AVRIL · DOUBLE PROGRAMME',
  matches: [
    { outcome:'VICTOIRE', home:'ROYAL', away:'HAWKS',     homeScore:5, awayScore:2,
      homeLogo: window.ROYAL_ASSETS?.royal, awayLogo: window.ROYAL_ASSETS?.teams.mirabel,
      scorers:'Gauthier (2), Leclerc, Robidoux, St-Pierre' },
    { outcome:'DÉFAITE',  home:'ROYAL', away:'SHERBROOKE', homeScore:1, awayScore:3,
      homeLogo: window.ROYAL_ASSETS?.royal, awayLogo: window.ROYAL_ASSETS?.teams.sherbrooke,
      scorers:'Tremblay-Côté' }
  ]
};

window.R05MultiResultats = R05MultiResultats;
