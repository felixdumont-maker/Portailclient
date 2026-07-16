/* global React */
const { useState } = React;

/**
 * R01 — SOIR DE MATCH
 * Gameday announcement. Top: ROYAL eyebrow + LE ROYAL hero + DATE pill.
 * Middle: Big VS — both team logo boxes flanking a giant "VS".
 * Lower: Glass info strip (date · time · arena). Footer: brand strip.
 */
function R01Gameday({ data = R01Gameday.defaults }) {
  const colors = data.colors || {};
  const colorVars = {};
  if (colors.bg)     colorVars['--template-bg'] = colors.bg;
  if (colors.pillBg) colorVars['--pill-bg']      = colors.pillBg;
  if (colors.pillFg) colorVars['--pill-fg']      = colors.pillFg;
  return (
    <div className="stage-1080" id="R01" style={colorVars}>
      <div style={{position:'absolute', inset:0, padding:'72px 80px', display:'flex', flexDirection:'column'}}>

        {/* Header eyebrow + hero title */}
        <div style={{display:'flex', flexDirection:'column', gap:14}}>
          <div className="kit-eyebrow">{data.eyebrow}</div>
          <div style={{
            fontFamily:'var(--font-display)', fontSize:124, lineHeight:0.86,
            letterSpacing:'var(--ls-display)', textShadow:'var(--shadow-press)',
            textTransform:'uppercase'
          }}>
            {data.heroLine1}<br/>{data.heroLine2}
          </div>
          <div style={{marginTop:8}}>
            <span className="kit-pill">{data.pill}</span>
          </div>
        </div>

        {/* Mid VS lockup */}
        <div style={{
          flex:1, display:'flex', alignItems:'center', justifyContent:'space-between',
          gap:32, padding:'40px 0'
        }}>
          <TeamBlock name={data.home.name} subtitle={data.home.subtitle} logo={data.home.logo} side="home"/>
          <div style={{
            fontFamily:'var(--font-display)', fontSize:200, lineHeight:1,
            letterSpacing:'-0.03em', textShadow:'4px 4px 0 rgba(0,0,0,0.35)'
          }}>VS</div>
          <TeamBlock name={data.away.name} subtitle={data.away.subtitle} logo={data.away.logo} side="away"/>
        </div>

        {/* Glass info strip */}
        <div style={{
          background:'var(--surface-glass)', backdropFilter:'blur(8px)',
          WebkitBackdropFilter:'blur(8px)',
          border:'1px solid var(--border-soft)', borderRadius:'var(--r-card)',
          padding:'22px 32px', display:'grid', gridTemplateColumns:'repeat(3, 1fr)',
          gap:24, textAlign:'center'
        }}>
          <InfoCell label="DATE" value={data.info.date}/>
          <InfoCell label="HEURE" value={data.info.time}/>
          <InfoCell label="ARÉNA" value={data.info.arena}/>
        </div>

        {/* Footer */}
        <div className="kit-footer" style={{marginTop:28}}>
          <span className="kit-footer-left">{data.footer.left}</span>
          <span className="kit-footer-right">{data.footer.right}</span>
        </div>
      </div>
    </div>
  );
}

function TeamBlock({ name, subtitle, logo, side }) {
  return (
    <div style={{display:'flex', flexDirection:'column', alignItems:'center', gap:16, flex:1}}>
      <div className="logo-box" style={{width:240, height:240, borderRadius:20}}>
        {logo ? <img src={logo} alt="" style={{width:'80%',height:'80%'}}/> : <span className="ph">LOGO<br/>{name}</span>}
      </div>
      <div style={{
        fontFamily:'var(--font-display)', fontSize:34, letterSpacing:'var(--ls-display)',
        textTransform:'uppercase', textAlign:'center', lineHeight:1
      }}>{name}</div>
      {subtitle && (
        <div style={{
          fontSize:13, fontWeight:700, letterSpacing:'0.18em', textTransform:'uppercase',
          color:'var(--fg-muted)'
        }}>{subtitle}</div>
      )}
    </div>
  );
}

function InfoCell({ label, value }) {
  return (
    <div style={{display:'flex', flexDirection:'column', gap:6}}>
      <div style={{fontSize:11, fontWeight:700, letterSpacing:'0.22em', color:'var(--fg-muted)'}}>{label}</div>
      <div style={{fontFamily:'var(--font-display)', fontSize:30, letterSpacing:'0.04em'}}>{value}</div>
    </div>
  );
}

R01Gameday.defaults = {
  colors: {},
  eyebrow: 'ROYAL DE SHAWINIGAN · LNHBF',
  heroLine1: 'SOIR DE',
  heroLine2: 'MATCH',
  pill: 'SAMEDI 18 AVRIL',
  home: { name: 'ROYAL', subtitle: 'SHAWINIGAN', logo: window.ROYAL_ASSETS?.royal },
  away: { name: 'HAWKS', subtitle: 'MIRABEL',    logo: window.ROYAL_ASSETS?.teams.mirabel },
  info: { date: '18 AVRIL', time: '19 H 30', arena: 'JACQUES-PLANTE' },
  footer: { left: 'NOS PARTENAIRES', right: 'COCKTAIL MÉDIA' }
};

window.R01Gameday = R01Gameday;
