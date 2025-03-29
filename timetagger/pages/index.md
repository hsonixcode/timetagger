% TimeTagger - Tag your time, get the insight
% An open source time tracker that feels lightweight and has powerful reporting.

<div class="hero-section">
  <div class="hero-content">
    <img src='timetagger_wd.svg' width='350px' class="hero-logo" />
    <h1 class='hero-title'><span class="highlight">Tag</span> your time,<br>get the <span class="highlight">insight</span>.</h1>
    <p class="hero-subtitle">An open source time tracker that feels lightweight and has powerful reporting.</p>
    
    <div class="cta-buttons">
      <a href='app/demo' class='cta-button'>
        <i class='fas'>\uf04b</i>&nbsp;&nbsp;Try Demo
      </a>
      <a href='app/' class='cta-button primary'>
        <i class='fas'>\uf04b</i>&nbsp;&nbsp;Start Tracking
      </a>
    </div>
  </div>
</div>

<div class="features-section">
  <div class="features-grid">
    <div class="feature-card">
      <i class="fas">\uf017</i>
      <h3>Simple & Lightweight</h3>
      <p>Easy to use interface with powerful features under the hood</p>
    </div>
    <div class="feature-card">
      <i class="fas">\uf03a</i>
      <h3>Powerful Reporting</h3>
      <p>Get insights into how you spend your time</p>
    </div>
    <div class="feature-card">
      <i class="fas">\uf0c2</i>
      <h3>Cloud Sync</h3>
      <p>Access your data from anywhere</p>
    </div>
  </div>
</div>

<div class="links-section">
  <h2>Resources</h2>
  <div class="links-grid">
    <a href="https://timetagger.app" class="link-card">
      <i class="fas">\uf015</i>
      <span>Main Website</span>
    </a>
    <a href="https://github.com/almarklein/timetagger" class="link-card">
      <i class="fas">\uf09b</i>
      <span>Source Code</span>
    </a>
    <a href="https://timetagger.readthedocs.io" class="link-card">
      <i class="fas">\uf02d</i>
      <span>Documentation</span>
    </a>
    <a href="https://github.com/almarklein/timetagger_cli" class="link-card">
      <i class="fas">\uf120</i>
      <span>CLI Tool</span>
    </a>
  </div>
</div>

<style>
.hero-section {
  text-align: center;
  padding: 4rem 2rem;
  background: linear-gradient(135deg, $prim1_clr 0%, darken($prim1_clr, 10%) 100%);
  color: white;
  border-radius: 8px;
  margin-bottom: 3rem;
}

.hero-content {
  max-width: 800px;
  margin: 0 auto;
}

.hero-logo {
  margin-bottom: 2rem;
}

.hero-title {
  font-size: 3rem;
  line-height: 1.2;
  margin-bottom: 1rem;
}

.highlight {
  border-bottom: 3px solid $acc_clr;
}

.hero-subtitle {
  font-size: 1.2rem;
  opacity: 0.9;
  margin-bottom: 2rem;
}

.cta-buttons {
  display: flex;
  gap: 1rem;
  justify-content: center;
}

.cta-button {
  display: inline-flex;
  align-items: center;
  padding: 1rem 2rem;
  border-radius: 4px;
  text-decoration: none;
  font-weight: bold;
  transition: transform 0.2s, box-shadow 0.2s;
  background: white;
  color: $prim1_clr;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
  }
  
  &.primary {
    background: $acc_clr;
    color: white;
  }
}

.features-section {
  padding: 4rem 2rem;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 2rem;
  max-width: 1200px;
  margin: 0 auto;
}

.feature-card {
  text-align: center;
  padding: 2rem;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  
  i {
    font-size: 2.5rem;
    color: $acc_clr;
    margin-bottom: 1rem;
  }
  
  h3 {
    margin-bottom: 1rem;
    color: $prim1_clr;
  }
  
  p {
    color: $prim3_clr;
    line-height: 1.6;
  }
}

.links-section {
  padding: 4rem 2rem;
  background: $bg1;
  border-radius: 8px;
  
  h2 {
    text-align: center;
    margin-bottom: 2rem;
    color: $prim1_clr;
  }
}

.links-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  max-width: 1200px;
  margin: 0 auto;
}

.link-card {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem;
  background: white;
  border-radius: 4px;
  text-decoration: none;
  color: $prim1_clr;
  transition: transform 0.2s, box-shadow 0.2s;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  }
  
  i {
    color: $acc_clr;
  }
}

@media (max-width: 768px) {
  .hero-title {
    font-size: 2rem;
  }
  
  .cta-buttons {
    flex-direction: column;
  }
  
  .features-grid {
    grid-template-columns: 1fr;
  }
}
</style>
