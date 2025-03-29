% TimeTagger - Project Overview
% Track and manage your time across projects

<div class="dashboard-header">
  <div class="header-content">
    <h1>Project Overview</h1>
    <div class="header-actions">
      <a href='app/' class='action-button'>
        <i class='fas'>\uf067</i>&nbsp;&nbsp;New Project
      </a>
    </div>
  </div>
</div>

<div class="dashboard-grid">
  <div class="dashboard-card">
    <div class="card-header">
      <h2>Active Projects</h2>
      <span class="count">3</span>
    </div>
    <div class="project-list">
      <div class="project-item">
        <div class="project-info">
          <h3>Website Redesign</h3>
          <p>UI/UX improvements and responsive design</p>
        </div>
        <div class="project-stats">
          <span class="time">12h 30m</span>
          <span class="status active">In Progress</span>
        </div>
      </div>
      <div class="project-item">
        <div class="project-info">
          <h3>Mobile App Development</h3>
          <p>iOS and Android app development</p>
        </div>
        <div class="project-stats">
          <span class="time">8h 15m</span>
          <span class="status active">In Progress</span>
        </div>
      </div>
      <div class="project-item">
        <div class="project-info">
          <h3>Backend API</h3>
          <p>RESTful API development and testing</p>
        </div>
        <div class="project-stats">
          <span class="time">5h 45m</span>
          <span class="status active">In Progress</span>
        </div>
      </div>
    </div>
  </div>

  <div class="dashboard-card">
    <div class="card-header">
      <h2>Recent Activity</h2>
    </div>
    <div class="activity-list">
      <div class="activity-item">
        <i class="fas">\uf017</i>
        <div class="activity-info">
          <p>Started tracking "Website Redesign"</p>
          <span class="time">2 hours ago</span>
        </div>
      </div>
      <div class="activity-item">
        <i class="fas">\uf00d</i>
        <div class="activity-info">
          <p>Stopped tracking "Mobile App Development"</p>
          <span class="time">4 hours ago</span>
        </div>
      </div>
      <div class="activity-item">
        <i class="fas">\uf0c2</i>
        <div class="activity-info">
          <p>Synced data across devices</p>
          <span class="time">5 hours ago</span>
        </div>
      </div>
    </div>
  </div>

  <div class="dashboard-card">
    <div class="card-header">
      <h2>Weekly Summary</h2>
    </div>
    <div class="summary-content">
      <div class="summary-item">
        <span class="label">Total Hours</span>
        <span class="value">26h 30m</span>
      </div>
      <div class="summary-item">
        <span class="label">Active Projects</span>
        <span class="value">3</span>
      </div>
      <div class="summary-item">
        <span class="label">Tasks Completed</span>
        <span class="value">12</span>
      </div>
    </div>
  </div>
</div>

<style>
.dashboard-header {
  background: linear-gradient(135deg, $prim1_clr 0%, darken($prim1_clr, 10%) 100%);
  color: white;
  padding: 2rem;
  border-radius: 8px;
  margin-bottom: 2rem;
}

.header-content {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 1rem;
}

.action-button {
  display: inline-flex;
  align-items: center;
  padding: 0.75rem 1.5rem;
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
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 2rem;
  max-width: 1200px;
  margin: 0 auto;
}

.dashboard-card {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid $sec1_clr;
}

.count {
  background: $acc_clr;
  color: white;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.9rem;
}

.project-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.project-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  background: $bg2;
  border-radius: 4px;
  transition: transform 0.2s;
  
  &:hover {
    transform: translateX(4px);
  }
}

.project-info h3 {
  margin: 0;
  color: $prim1_clr;
}

.project-info p {
  margin: 0.25rem 0 0;
  color: $prim3_clr;
  font-size: 0.9rem;
}

.project-stats {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.5rem;
}

.time {
  color: $prim1_clr;
  font-weight: bold;
}

.status {
  font-size: 0.8rem;
  padding: 0.25rem 0.5rem;
  border-radius: 12px;
  
  &.active {
    background: #e6f4ea;
    color: #1e7e34;
  }
}

.activity-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.activity-item {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 0.75rem;
  background: $bg2;
  border-radius: 4px;
  
  i {
    color: $acc_clr;
    font-size: 1.2rem;
  }
}

.activity-info {
  flex: 1;
  
  p {
    margin: 0;
    color: $prim1_clr;
  }
  
  .time {
    font-size: 0.8rem;
    color: $prim3_clr;
  }
}

.summary-content {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 1rem;
}

.summary-item {
  text-align: center;
  padding: 1rem;
  background: $bg2;
  border-radius: 4px;
  
  .label {
    display: block;
    color: $prim3_clr;
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
  }
  
  .value {
    display: block;
    color: $prim1_clr;
    font-size: 1.5rem;
    font-weight: bold;
  }
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: 1rem;
    text-align: center;
  }
  
  .header-actions {
    flex-direction: column;
  }
  
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}
</style>
