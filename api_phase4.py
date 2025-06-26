from flask import Flask, request, jsonify, send_file, render_template, render_template_string
import joblib
import pandas as pd
import csv
from datetime import datetime
import os

# Load model + scaler
model = joblib.load("iso_forest_model_tuned.pkl")
scaler = joblib.load("scaler_tuned.pkl")

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    input_df = pd.DataFrame([data])

    input_df['risk_score'] = (
        input_df['ip_reputation_score'] * 0.5 +
        input_df['failed_logins'] * 0.2 +
        input_df['unusual_time_access'] * 0.3
    )

    expected_columns = [
        'network_packet_size', 'login_attempts', 'session_duration',
        'ip_reputation_score', 'failed_logins', 'unusual_time_access',
        'protocol_type_ICMP', 'protocol_type_TCP', 'protocol_type_UDP',
        'encryption_used_AES', 'encryption_used_DES',
        'browser_type_Chrome', 'browser_type_Edge', 'browser_type_Firefox',
        'browser_type_Safari', 'browser_type_Unknown',
        'risk_score'
    ]

    for col in expected_columns:
        if col not in input_df.columns:
            input_df[col] = 0

    input_df = input_df[expected_columns]
    scaled_input = scaler.transform(input_df)
    prediction = model.predict(scaled_input)
    anomaly_flag = int(prediction[0] == -1)

    # Log
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "anomaly": anomaly_flag,
        **data
    }

    log_file = "prediction_log.csv"
    with open(log_file, "a", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=log_entry.keys())
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow(log_entry)

    return jsonify({
        "anomaly": anomaly_flag,
        "message": "Anomaly detected!" if anomaly_flag else "Session is normal."
    })

@app.route('/report', methods=['GET'])
def report():
    # Simple HTML template with links
    html = """
    <h1>Masquerade Detection Report</h1>
    <p><a href="/download/log">Download Prediction Log (CSV)</a></p>
    <p><a href="/download/summary">Download Summary Report (CSV)</a></p>
    <p><img src="/static/anomaly_summary_plot.png" alt="Anomaly Summary Plot"></p>
    <p><img src="/static/anomaly_pie_chart.png" alt="Anomaly Pie Chart"></p>
    <p><img src="/static/anomaly_timeline_plot.png" alt="Anomaly Timeline Plot"></p>
    """
    return render_template_string(html)

@app.route('/download/log')
def download_log():
    return send_file("prediction_log.csv", as_attachment=True)

@app.route('/download/summary')
def download_summary():
    return send_file("prediction_summary_report.csv", as_attachment=True)

# @app.route('/dashboard')
# def dashboard():
#     df = pd.read_csv("prediction_log.csv")
#     # Compute metrics
#     total = len(df)
#     anomalies = df['anomaly'].sum()
#     normal = total - anomalies
#     anomaly_rate = (anomalies / total) * 100 if total > 0 else 0

#     # Prepare data for charts
#     summary = {
#         'total': total,
#         'anomalies': anomalies,
#         'normal': normal,
#         'anomaly_rate': anomaly_rate,
#         'df_tail': df.tail(50).to_dict(orient='records')
#     }

#     return render_template("dashboard.html", summary=summary)

@app.route('/dashboard')
def dashboard():
    try:
        df = pd.read_csv("prediction_log.csv")
        total = len(df)
        anomalies = df['anomaly'].sum()
        normal = total - anomalies
        anomaly_rate = (anomalies / total) * 100 if total > 0 else 0

        summary = {
            'total': total,
            'anomalies': anomalies,
            'normal': normal,
            'anomaly_rate': anomaly_rate,
            'df_tail': df.tail(50).to_dict(orient='records') if total > 0 else []
        }
    except Exception as e:
        summary = {
            'total': 0,
            'anomalies': 0,
            'normal': 0,
            'anomaly_rate': 0,
            'df_tail': []
        }

    return render_template("dashboard.html", summary=summary)

if __name__ == '__main__':
    # Make sure static directory exists and has your plots
    if not os.path.exists('static'):
        os.makedirs('static')
    os.system('cp anomaly_summary_plot.png static/')
    os.system('cp anomaly_pie_chart.png static/')
    os.system('cp anomaly_timeline_plot.png static/')
    app.run(debug=True)


