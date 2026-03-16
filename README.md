# 🛡️ AI Security Dashboard (KMRL Security Management System)

A simplified, fully self-contained AI Security Chatbot and Risk Assessment Dashboard built using Python, Streamlit, and Plotly. This application simulates a security environment where user activities (like document views, downloads, exports, and shares) are monitored, risk scores are calculated based on behavioral patterns, and a security chatbot can answer queries regarding document access policies.

## 🌟 Key Features

1. **🏠 Dashboard Overview**:
   - Visualizes real-time security events for individual users.
   - Calculates a **Risk Score (0-100)** based on an automated Risk Engine.
   - Analyzes recent activities to detect anomalies (e.g., bulk exports, off-hours access, cross-department access).
   - Displays a Daily Activity Pattern chart.

2. **🤖 AI Security Chatbot**:
   - Understands natural language queries related to document sharing/export policies.
   - Classifies documents based on their ID (Safety, HR, Finance, Legal, PII, General).
   - Provides context-aware security decisions based on the user's current risk score and predefined organizational policies.
   - Handles access requests and suspicious activity reporting.

3. **📊 Risk Analysis**:
   - Provides an organizational overview of risk scores across all system users.
   - Comparative bar charts mapping user risk levels (Green/Yellow/Red).
   - Pie charts showing activity distribution across different departments (Operations, Finance, HR, Legal, etc.).

## 🚀 Getting Started

Follow the instructions below to get a copy of the project up and running on your local machine.

### Prerequisites

You need Python installed on your system. It is recommended to use Python 3.8 or higher.

To check if you have Python installed, open your command prompt (cmd) and run:
```cmd
python --version
```

### Installation

1. **Open your Command Prompt (cmd) or PowerShell**.
2. **Navigate to the inner project directory**. Make sure you are inside the folder containing `main.py` and `requirements.txt`:
   ```cmd
   cd "C:\Users\kakum\Desktop\AI & ML PROJECTS\SIH-ai-security-dashboard-main\SIH-ai-security-dashboard-main"
   ```
3. **Install the required dependencies** using `pip`:
   ```cmd
   python -m pip install -r requirements.txt
   ```
   *(Note: Using `python -m pip` ensures that pip installs packages to the correct Python environment).*

### Running the Application

To start the Streamlit web application, run the following command in your terminal:

```cmd
python -m streamlit run main.py
```

*If the above command doesn't work depending on your Python aliases, you can also try:*
- `py -m streamlit run main.py` (Windows)
- `python3 -m streamlit run main.py` (Mac/Linux)

Once the server starts up, your default web browser will automatically open and navigate to the application (typically at `http://localhost:8501`).

## 📁 Project Structure

- `main.py` : The core application file. Contains the entire stack including dummy data generation, structural dataclasses, simple risk engine rules, policy engine logic, and the Streamlit frontend.
- `requirements.txt` : Lists all required Python dependencies (`streamlit`, `plotly`, `pandas`, `numpy`).

## 🛠️ Built With
- [Python](https://www.python.org/) - The programming language used.
- [Streamlit](https://streamlit.io/) - The web framework used to turn data scripts into shareable web apps.
- [Plotly Express](https://plotly.com/python/plotly-express/) - The graphing library used for interactive UI charts.

## 🔐 Security Policies Simulated
The built-in engine restricts actions based on the document class:
- **Safety / Finance / General**: allowed for internal sharing; exports are generally allowed but restricted if anomalous behavior occurs.
- **HR / PII / Legal**: Highly sensitive documents. Sharing and exports are heavily restricted or outright denied.
- **Risk Override**: If a user's calculated risk score is over `70`, standard actions are aggressively blocked or flagged for approval regardless of usual permissibility.
