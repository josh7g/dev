from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()

class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)  # New column for reranked results
    
    def to_dict(self):
        return {
            'id': self.id,
            'repository_name': self.repository_name,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
            'error': self.error
        }



class GitLabAnalysisResult(db.Model):
    """Model for storing GitLab repository analysis results"""
    __tablename__ = 'gitlab_analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(255), nullable=False)
    project_url = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)
    results = db.Column(JSONB)
    rerank = db.Column(JSONB)
    error = db.Column(db.Text)

    __table_args__ = (
        db.Index('idx_gitlab_analysis_project', 'project_id'),
        db.Index('idx_gitlab_analysis_user', 'user_id'),
        db.Index('idx_gitlab_analysis_timestamp', 'timestamp'),
        db.Index('idx_gitlab_analysis_status', 'status')
    )

    def __repr__(self):
        return f'<GitLabAnalysisResult {self.project_id} {self.timestamp}>'