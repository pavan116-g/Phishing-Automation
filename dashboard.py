from flask import Flask, render_template, jsonify
import db
import config

app = Flask(__name__)

# Initialize database on startup
db.init_db()

@app.route('/')
def index():
    """Renders the main dashboard HTML, passing the list of analyzed emails."""
    emails = db.get_all_emails()
    return render_template('dashboard.html', emails=emails)

@app.route('/api/emails')
def api_emails():
    """Returns all emails in the database as a JSON list."""
    emails = db.get_all_emails()
    return jsonify(emails)

@app.route('/api/stats')
def api_stats():
    """Returns dynamic statistics about analyzed emails."""
    emails = db.get_all_emails()
    total = len(emails)
    phishing = sum(1 for e in emails if e.get('verdict') == 'PHISHING')
    safe = sum(1 for e in emails if e.get('verdict') == 'SAFE')
    
    # emails is sorted by analyzed_at descending, so the first index has the latest check
    last_checked = emails[0].get('analyzed_at') if emails else None
    
    return jsonify({
        'total': total,
        'phishing': phishing,
        'safe': safe,
        'last_checked': last_checked
    })

if __name__ == '__main__':
    # Run the Flask server on 0.0.0.0:5000 with debug disabled
    app.run(host='0.0.0.0', port=5000, debug=False)
