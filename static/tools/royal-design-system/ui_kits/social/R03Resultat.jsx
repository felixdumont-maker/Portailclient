/* global React */
/**
 * R03 — RÉSULTAT DE MATCH (single result)
 * Top eyebrow VICTOIRE/DÉFAITE pill. Center: scoreboard with team logos
 * flanking a giant final score. Lower: scorers list (buteuses) + meta.
 */
function R03Resultat({ data = R03Resultat.defaults }) {
  const win = data.outcome === 'VICTOIRE';
  const colors = data.colors || {};
  const colorVars = {};
  if (colors.bg)     colorVars['--template-bg'] = colors.bg;
  if (colors.pillBg) colorVars['--pill-bg']      = colors.pillBg;
  if (colors.pillFg) colorVars['--pill-fg']      = colors.pillFg;
  return (
    <div className="stage-1080" id="R03" style={colorVars}>
      <div style={{position:'absolute', inset:0, padding:'72px 80px', display:'flex', flexDirection:'column', gap:28}}>

        {/* Header */}
        <div style={{display:'flex', flexDirection:'column', gap:16}}>
          <div className="kit-eyebrow">{data.eyebrow}</div>
          <div style={{display:'flex', alignItems:'center', gap:16}}>
            <span className="kit-pill" style={{
              background: win ? 'var(--win-bg)' : 'var(--loss-bg)',
              color: win ? 'var(--win-fg)' : 'var(--loss-fg)'
            }}>{data.outcome}</span>
            <span style={{fontSize:13, fontWeight:700, letterSpacing:'0.2em', color:'var(--fg-muted)'}}>
              {data.subEyebrow}
            </span>
          </div>
          <div style={{
            fontFamily:'var(--font-display)', fontSize:96, lineHeight:0.88,
            letterSpacing:'var(--ls-display)', textShadow:'var(--shadow-press)',
            textTransform:'uppercase'
          }}>{data.title}</div>
        </div>

        {/* Scoreboard */}
        <div style={{
          flex:1, background:'var(--surface-deep)',
          border:'1px solid var(--border-soft)', borderRadius:'var(--r-card)',
          padding:'40px 48px', display:'flex', alignItems:'center',
          justifyContent:'space-between', gap:24, position:'relative', overflow:'hidden'
        }}>
          {/* left accent bar */}
          <div style={{
            position:'absolute', left:0, top:0, bottom:0, width:8,
            background: win ? 'var(--win-fg)' : 'var(--loss-fg)'
          }}/>
          <ScoreSide team={data.home} score={data.homeScore} winner={win}/>
          <div style={{
            fontFamily:'var(--font-display)', fontSize:36, color:'var(--fg-muted)',
            letterSpacing:'0.2em'
          }}>FINAL</div>
          <ScoreSide team={data.away} score={data.awayScore} winner={!win} alignRight/>
        </div>

        {/* Buteuses + meta */}
        <div style={{display:'grid', gridTemplateColumns:'2fr 1fr', gap:20}}>
          <div style={{
            background:'var(--surface-mid)', border:'1px solid var(--border-soft)',
            borderRadius:'var(--r-md)', padding:'20px 24px'
          }}>
            <div style={{fontSize:11, fontWeight:700, letterSpacing:'0.22em', color:'var(--fg-muted)', marginBottom:14}}>BUTEUSES</div>
            <div style={{display:'flex', flexWrap:'wrap', gap:8}}>
              {data.scorers.map((s, i) => (
                <span key={i} style={{
                  background:'var(--surface-glass)', border:'1px solid var(--border-soft)',
                  padding:'8px 14px', borderRadius:'var(--r-pill)',
                  fontSize:14, fontWeight:600
                }}>
                  {s.name} <span style={{color:'var(--fg-tertiary)', marginLeft:6}}>×{s.goals}</span>
                </span>
              ))}
            </div>
          </div>
          <div style={{
            background:'var(--surface-mid)', border:'1px solid var(--border-soft)',
            borderRadius:'var(--r-md)', padding:'20px 24px'
          }}>
            <div style={{fontSize:11, fontWeight:700, letterSpacing:'0.22em', color:'var(--fg-muted)', marginBottom:10}}>GARDIENNE</div>
            <div style={{fontFamily:'var(--font-display)', fontSize:30, lineHeight:1.05}}>{data.goalie.name}</div>
            <div style={{fontSize:13, color:'var(--fg-tertiary)', marginTop:4}}>{data.goalie.line}</div>
          </div>
        </div>

        {/* Footer */}
        <div className="kit-footer">
          <span className="kit-footer-left">{data.footer.left}</span>
          <span className="kit-footer-right">COCKTAIL MÉDIA</span>
        </div>
      </div>
    </div>
  );
}

function ScoreSide({ team, score, winner, alignRight }) {
  return (
    <div style={{
      display:'flex', flexDirection:'column', alignItems: alignRight ? 'flex-end' : 'flex-start',
      gap:14, flex:1
    }}>
      <div className="logo-box" style={{width:120, height:120, borderRadius:14}}>
        {team.logo ? <img src={team.logo} alt="" style={{width:'80%',height:'80%'}}/> : <span className="ph">{team.name}</span>}
      </div>
      <div style={{
        fontFamily:'var(--font-display)', fontSize:32, letterSpacing:'var(--ls-display)',
        textTransform:'uppercase'
      }}>{team.name}</div>
      <div style={{
        fontFamily:'var(--font-display)',
        fontSize: winner ? 168 : 132,
        lineHeight:0.9, letterSpacing:'-0.04em',
        color: winner ? 'var(--fg-primary)' : 'var(--fg-tertiary)',
        textShadow: winner ? 'var(--shadow-press)' : 'none'
      }}>{score}</div>
    </div>
  );
}

R03Resultat.defaults = {
  colors: {},
  eyebrow: 'RÉSULTAT · LNHBF',
  subEyebrow: 'SAMEDI 12 AVRIL · ARÉNA JACQUES-PLANTE',
  outcome: 'VICTOIRE',
  title: 'BELLE\nVICTOIRE',
  home: { name: 'ROYAL',  logo: window.ROYAL_ASSETS?.royal },
  away: { name: 'HAWKS',  logo: window.ROYAL_ASSETS?.teams.mirabel },
  homeScore: 5,
  awayScore: 2,
  scorers: [
    { name: 'C. GAUTHIER', goals: 2 },
    { name: 'M. LECLERC', goals: 1 },
    { name: 'A. ROBIDOUX', goals: 1 },
    { name: 'J. ST-PIERRE', goals: 1 }
  ],
  goalie: { name: 'L. TREMBLAY', line: '24 arrêts sur 26' },
  footer: { left: 'NOS PARTENAIRES' }
};

window.R03Resultat = R03Resultat;
