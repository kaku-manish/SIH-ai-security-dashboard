"""
Simplified AI Security Chatbot - Streamlit Web Application
=========================================================
Version without heavy pandas compilation requirements

Installation: pip install streamlit plotly
Run with: streamlit run simple_app.py
"""

import streamlit as st
import json
import random
import re
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import plotly.express as px
import plotly.graph_objects as go

# Set page configuration
st.set_page_config(
    page_title="AI Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main > div { padding-top: 2rem; }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem; border-radius: 10px; color: white; margin: 0.5rem 0;
    }
    .risk-high { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); }
    .risk-medium { background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%); }
    .risk-low { background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%); }
    .chat-message { padding: 1rem; border-radius: 10px; margin: 0.5rem 0; }
    .user-message { background-color: #e3f2fd; border-left: 4px solid #2196f3; }
    .bot-message { background-color: #f3e5f5; border-left: 4px solid #9c27b0; }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# SIMPLIFIED DATA STRUCTURES (No Pandas Required)
# =============================================================================

@dataclass
class SecurityEvent:
    user_id: str
    action: str
    doc_id: str
    department: str
    sensitivity: str
    timestamp: datetime
    device_managed: bool
    ip: str
    location: str
    count: int = 1

class SimpleDataHandler:
    def __init__(self, events: List[SecurityEvent]):
        self.events = events
    
    def filter_by_user(self, user_id: str) -> List[SecurityEvent]:
        return [e for e in self.events if e.user_id == user_id]
    
    def filter_by_timeframe(self, events: List[SecurityEvent], hours: int) -> List[SecurityEvent]:
        cutoff = datetime.now() - timedelta(hours=hours)
        return [e for e in events if e.timestamp >= cutoff]
    
    def get_users(self) -> List[str]:
        return list(set(e.user_id for e in self.events))
    
    def count_by_action(self, events: List[SecurityEvent], action: str) -> int:
        return sum(e.count for e in events if e.action == action)
    
    def get_departments_count(self, events: List[SecurityEvent]) -> int:
        return len(set(e.department for e in events))
    
    def count_off_hours(self, events: List[SecurityEvent]) -> int:
        return len([e for e in events if e.timestamp.hour < 7 or e.timestamp.hour > 20])
    
    def get_sensitive_ratio(self, events: List[SecurityEvent]) -> float:
        if not events:
            return 0.0
        sensitive = len([e for e in events if e.sensitivity in ['PII', 'Finance', 'HR', 'Legal']])
        return sensitive / len(events)

# =============================================================================
# CORE SECURITY COMPONENTS
# =============================================================================

class SimpleRiskEngine:
    def __init__(self, data_handler: SimpleDataHandler):
        self.data_handler = data_handler
    
    def calculate_risk_features(self, user_id: str, window_hours: int = 24) -> Dict[str, float]:
        user_events = self.data_handler.filter_by_user(user_id)
        recent_events = self.data_handler.filter_by_timeframe(user_events, window_hours)
        
        if not recent_events:
            return {
                'total_events': 0.0, 'exports': 0.0, 'shares': 0.0, 'downloads': 0.0,
                'views': 0.0, 'reveals': 0.0, 'policy_changes': 0.0, 'sensitive_ratio': 0.0,
                'department_diversity': 0.0, 'off_hours_events': 0.0
            }
        
        return {
            'total_events': float(len(recent_events)),
            'exports': float(self.data_handler.count_by_action(recent_events, 'export')),
            'shares': float(self.data_handler.count_by_action(recent_events, 'share')),
            'downloads': float(self.data_handler.count_by_action(recent_events, 'download')),
            'views': float(self.data_handler.count_by_action(recent_events, 'view')),
            'reveals': float(self.data_handler.count_by_action(recent_events, 'reveal_sensitive_field')),
            'policy_changes': float(self.data_handler.count_by_action(recent_events, 'policy_change')),
            'sensitive_ratio': self.data_handler.get_sensitive_ratio(recent_events),
            'department_diversity': float(self.data_handler.get_departments_count(recent_events)),
            'off_hours_events': float(self.data_handler.count_off_hours(recent_events))
        }
    
    def calculate_risk_score(self, user_id: str) -> Tuple[float, List[str]]:
        features = self.calculate_risk_features(user_id)
        risk_score = 0.0
        reasons = []
        
        # Export volume risk
        if features['exports'] >= 50:
            risk_score += 35
            reasons.append(f"🚨 Bulk export spike: {int(features['exports'])} files")
        elif features['exports'] >= 10:
            risk_score += 20
            reasons.append(f"⚠️ High export volume: {int(features['exports'])} files")
        
        # Cross-department access
        if features['department_diversity'] >= 4:
            risk_score += 20
            reasons.append(f"🏢 Many departments accessed: {int(features['department_diversity'])}")
        elif features['department_diversity'] >= 2:
            risk_score += 10
            reasons.append(f"🔄 Cross-department access: {int(features['department_diversity'])}")
        
        # Off-hours activity
        if features['off_hours_events'] >= 10:
            risk_score += 15
            reasons.append(f"🌙 Off-hours activity: {int(features['off_hours_events'])} events")
        elif features['off_hours_events'] >= 3:
            risk_score += 8
            reasons.append("⏰ Some off-hours activity")
        
        # Sensitive document access
        if features['sensitive_ratio'] >= 0.6:
            risk_score += 20
            reasons.append(f"🔒 High sensitive doc ratio: {features['sensitive_ratio']:.2f}")
        elif features['sensitive_ratio'] >= 0.3:
            risk_score += 10
            reasons.append(f"🔐 Elevated sensitive doc ratio: {features['sensitive_ratio']:.2f}")
        
        # Policy changes
        if features['policy_changes'] >= 1:
            risk_score += 10
            reasons.append("⚙️ Recent policy changes")
        
        risk_score = max(0.0, min(100.0, risk_score))
        if risk_score == 0.0:
            reasons.append("✅ No risk indicators detected")
        
        return float(risk_score), reasons

# Security Policies (same as before)
SECURITY_POLICIES = {
    "document_classes": {
        "Safety": {"share_internal": True, "share_external": False, "export": "restricted"},
        "HR": {"share_internal": False, "share_external": False, "export": "denied"},
        "PII": {"share_internal": False, "share_external": False, "export": "denied"},
        "Finance": {"share_internal": True, "share_external": False, "export": "restricted"},
        "Legal": {"share_internal": False, "share_external": False, "export": "restricted"},
        "General": {"share_internal": True, "share_external": False, "export": "allowed"}
    },
    "security_controls": {
        "default": ["watermark", "view_only", "expiry_72h"],
        "restricted_export": ["watermark", "dense_watermark", "view_only", "step_up_mfa", "second_approver"]
    },
    "explanations": {
        "Safety": "Safety bulletins are internal-shareable with watermark and expiry; external sharing is prohibited.",
        "HR": "HR documents contain confidential information; sharing/exporting is prohibited without exception.",
        "PII": "PII documents cannot be shared or exported due to privacy regulations.",
        "Finance": "Finance documents are internal-shareable; bulk export is restricted and requires approval.",
        "Legal": "Legal documents are highly sensitive; exports require approval; sharing is limited.",
        "General": "General documents can be shared internally with watermark; external sharing is blocked by default."
    }
}

class PolicyEngine:
    def __init__(self, policies: dict):
        self.policies = policies
    
    def make_access_decision(self, action: str, document_class: str, risk_score: float, target: str = None):
        policies = self.policies
        class_rules = policies['document_classes'].get(document_class, policies['document_classes']['General'])
        explanation = policies['explanations'].get(document_class, "Default policy applies")
        
        if risk_score >= 70 and action in ("export", "share"):
            return ("require_approval", ["step_up_mfa", "second_approver", "dense_watermark"],
                   f"High risk score ({risk_score:.0f}) requires approval", ["High risk threshold exceeded"])
        
        if action == "share":
            is_external = bool(target and "external" in target.lower())
            if is_external and not class_rules["share_external"]:
                return ("deny", ["deny"], explanation, ["External sharing not permitted"])
            if class_rules["share_internal"]:
                return ("allow_with_controls", policies["security_controls"]["default"], explanation, [])
            return ("deny", ["deny"], explanation, ["Internal sharing not permitted"])
        
        if action == "export":
            export_policy = class_rules.get("export", "restricted")
            if export_policy == "denied":
                return ("deny", ["deny"], explanation, ["Export denied"])
            if export_policy == "restricted":
                return ("allow_with_controls", policies["security_controls"]["restricted_export"], explanation, ["Restricted export"])
            return ("allow", [], explanation, [])
        
        if action in ("download", "view"):
            if document_class in ("HR", "PII", "Finance", "Legal", "Safety"):
                return ("allow_with_controls", ["watermark"], explanation, [])
            return ("allow", [], explanation, [])
        
        return ("deny", ["deny"], "Unknown action", ["No matching policy"])

class SecurityChatbot:
    def __init__(self, risk_engine: SimpleRiskEngine, policy_engine: PolicyEngine):
        self.risk_engine = risk_engine
        self.policy_engine = policy_engine
    
    @staticmethod
    def classify_document(doc_id: str) -> str:
        doc_id_upper = doc_id.upper()
        if doc_id_upper.startswith("SB-") or "SAFETY" in doc_id_upper:
            return "Safety"
        if doc_id_upper.startswith("INV-") or doc_id_upper.startswith("FIN-"):
            return "Finance"
        if doc_id_upper.startswith("HR-"):
            return "HR"
        if doc_id_upper.startswith("LEG-") or "LEGAL" in doc_id_upper:
            return "Legal"
        if "PII" in doc_id_upper or "PERSONAL" in doc_id_upper:
            return "PII"
        return "General"
    
    @staticmethod
    def detect_user_intent(message: str) -> str:
        message_lower = message.lower()
        if re.search(r"\bwhy (was )?(it )?blocked\b|\bwhy denied\b|\bwhy not allowed\b", message_lower):
            return "why_blocked"
        if "share" in message_lower:
            return "can_share"
        if "export" in message_lower:
            return "can_export"
        if "policy" in message_lower:
            return "show_policy"
        if "request access" in message_lower or "need access" in message_lower:
            return "request_access"
        if "report suspicious" in message_lower or "not me" in message_lower:
            return "report_suspicious"
        return "unknown"
    
    @staticmethod
    def extract_document_id(message: str) -> str:
        match = re.search(r"([A-Z]{2,5}-\d{4,}-?\d*)", message.upper())
        return match.group(1) if match else "GEN-DEFAULT-01"
    
    def process_query(self, user_id: str, message: str, target: str = None) -> dict:
        intent = self.detect_user_intent(message)
        doc_id = self.extract_document_id(message)
        doc_class = self.classify_document(doc_id)
        risk_score, _ = self.risk_engine.calculate_risk_score(user_id)
        
        if intent in ("can_share", "can_export"):
            action = "share" if intent == "can_share" else "export"
            decision, controls, explanation, reasons = self.policy_engine.make_access_decision(
                action, doc_class, risk_score, target=target)
            
            if decision == "deny":
                answer = f"❌ **Not Allowed**\n\n**Reason:** {explanation}"
            elif decision == "require_approval":
                answer = f"⏸ **Requires Approval**\n\nDue to high risk score ({risk_score:.0f}), approval needed."
            elif decision == "allow_with_controls":
                controls_text = ', '.join(controls)
                answer = f"✅ **Allowed with Controls**\n\n**Security Controls:** {controls_text}\n\n**Policy:** {explanation}"
            else:
                answer = f"✅ **Allowed**\n\n**Policy:** {explanation}"
            
            return {"answer": answer, "decision": decision, "controls": controls, "risk_score": risk_score,
                   "reasons": reasons, "document_class": doc_class, "document_id": doc_id}
        
        if intent == "show_policy":
            _, _, explanation, _ = self.policy_engine.make_access_decision("view", doc_class, risk_score)
            return {"answer": f"📋 **Policy for {doc_class} Documents**\n\n{explanation}", "document_class": doc_class}
        
        if intent == "why_blocked":
            return {"answer": f"🔍 **Analysis Result**\n\nYour current risk score is **{risk_score:.0f}**.", "risk_score": risk_score}
        
        if intent == "report_suspicious":
            return {"answer": "🎫 **Security Ticket Created**\n\nThank you for reporting. A security ticket has been created."}
        
        if intent == "request_access":
            return {"answer": "📝 **Access Request Noted**\n\nPlease contact your manager or security team for approval."}
        
        return {"answer": "🤖 **AI Security Assistant**\n\nI can help you with:\n- 'Can I share/export [document]?'\n- 'Why was it blocked?'\n- 'Show policy for [document]'\n\nInclude a document ID like SB-2025-12."}

# =============================================================================
# DATA GENERATION
# =============================================================================

@st.cache_data
def generate_sample_events() -> List[SecurityEvent]:
    random.seed(42)
    users = ["admin_kmrl01", "sc_raj", "hr_lead", "fin_mgr"] + [f"user_{i}" for i in range(1, 11)]
    departments = ["Operations", "Finance", "HR", "Legal", "Procurement", "Engineering"]
    sens_classes = ["General", "Safety", "Finance", "HR", "PII", "Legal"]
    actions = ["view", "download", "export", "share", "reveal_sensitive_field", "policy_change"]
    
    events = []
    now = datetime.now()
    
    for user in users:
        daily_events = {"admin_kmrl01": 100, "hr_lead": 60, "fin_mgr": 70, "sc_raj": 45}.get(user, 25)
        
        for day in range(7):
            base_day = now - timedelta(days=day)
            for _ in range(daily_events):
                hour = random.choice([8,9,10,11,12,13,14,15,16,17,18,19,20])
                timestamp = base_day.replace(hour=hour, minute=random.randint(0, 59))
                department = random.choice(departments)
                sensitivity = random.choice(sens_classes)
                action = random.choices(actions, weights=[60, 15, 5, 10, 9, 1], k=1)[0]
                
                events.append(SecurityEvent(
                    user_id=user,
                    action=action,
                    doc_id=f"{department[:3].upper()}-{random.randint(1000, 9999)}",
                    department=department,
                    sensitivity=sensitivity,
                    timestamp=timestamp,
                    device_managed=True,
                    ip=f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    location="KOCHI",
                    count=random.choice([1, 1, 5, 10]) if action == "export" else 1
                ))
        
        # Add anomalies for admin
        if user == "admin_kmrl01":
            anomaly_day = now - timedelta(days=random.randint(1, 7))
            for _ in range(60):
                timestamp = anomaly_day.replace(hour=random.choice([22, 23, 0, 1, 2]))
                events.append(SecurityEvent(
                    user_id=user, action="export",
                    doc_id=f"{random.choice(departments)[:3].upper()}-{random.randint(1000, 9999)}",
                    department=random.choice(departments),
                    sensitivity=random.choice(["Finance", "HR", "PII", "Legal"]),
                    timestamp=timestamp, device_managed=True,
                    ip=f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    location="KOCHI", count=1
                ))
    
    return events

# =============================================================================
# STREAMLIT APP
# =============================================================================

def main():
    # Initialize system
    events = generate_sample_events()
    data_handler = SimpleDataHandler(events)
    risk_engine = SimpleRiskEngine(data_handler)
    policy_engine = PolicyEngine(SECURITY_POLICIES)
    chatbot = SecurityChatbot(risk_engine, policy_engine)
    
    # App Header
    st.title("🛡️ AI Security Dashboard")
    st.markdown("**KMRL Security Management System** - AI-Powered Risk Assessment & Policy Chatbot")
    
    # Sidebar
    st.sidebar.title("🔧 Navigation")
    users = data_handler.get_users()
    selected_user = st.sidebar.selectbox("👤 Select User:", sorted(users), index=0)
    page = st.sidebar.radio("📄 Select Page:", ["🏠 Dashboard", "🤖 Security Chatbot", "📊 Risk Analysis"])
    
    # Initialize chat history
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    
    # =============================================================================
    # DASHBOARD PAGE
    # =============================================================================
    if page == "🏠 Dashboard":
        st.header(f"📊 Security Overview - {selected_user}")
        
        # Get risk score
        risk_score, risk_reasons = risk_engine.calculate_risk_score(selected_user)
        
        # Risk classification
        if risk_score >= 70:
            risk_level, risk_color, risk_class = "HIGH", "🔴", "risk-high"
        elif risk_score >= 30:
            risk_level, risk_color, risk_class = "MEDIUM", "🟡", "risk-medium"
        else:
            risk_level, risk_color, risk_class = "LOW", "🟢", "risk-low"
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card {risk_class}">
                <h3>{risk_color} Risk Score</h3>
                <h1>{risk_score:.0f}/100</h1>
                <p>Risk Level: {risk_level}</p>
            </div>
            """, unsafe_allow_html=True)
        
        user_events = data_handler.filter_by_user(selected_user)
        recent_events = data_handler.filter_by_timeframe(user_events, 24)
        
        with col2:
            st.metric("📈 Events (24h)", len(recent_events))
        with col3:
            exports = data_handler.count_by_action(recent_events, 'export')
            st.metric("📤 Exports (24h)", exports)
        with col4:
            depts = data_handler.get_departments_count(recent_events)
            st.metric("🏢 Departments", depts)
        
        # Risk reasons
        st.subheader("🔍 Risk Analysis")
        for reason in risk_reasons[:5]:
            if "No risk" in reason:
                st.success(reason)
            elif any(x in reason for x in ["🚨", "⚠️"]):
                st.error(reason)
            else:
                st.warning(reason)
        
        # Activity chart
        st.subheader("📅 Activity Pattern")
        if recent_events:
            daily_counts = {}
            for event in user_events[-50:]:  # Last 50 events
                date = event.timestamp.date()
                daily_counts[date] = daily_counts.get(date, 0) + 1
            
            if daily_counts:
                dates = list(daily_counts.keys())
                counts = list(daily_counts.values())
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=dates, y=counts, mode='lines+markers', name='Daily Events'))
                fig.update_layout(title='Daily Activity Pattern', height=300)
                st.plotly_chart(fig, use_container_width=True)
        
        # Recent activities
        st.subheader("📝 Recent Activities")
        if recent_events:
            for event in recent_events[-10:]:
                st.write(f"**{event.timestamp.strftime('%H:%M')}** - {event.action.title()} - {event.doc_id} ({event.sensitivity})")
        else:
            st.info("No recent activities.")
    
    # =============================================================================
    # CHATBOT PAGE
    # =============================================================================
    elif page == "🤖 Security Chatbot":
        st.header("🤖 AI Security Assistant")
        st.markdown(f"**Current User:** {selected_user}")
        
        # Quick actions
        st.subheader("🚀 Quick Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📋 Show HR Policy"):
                response = chatbot.process_query(selected_user, "Show policy for HR-2025-001")
                st.session_state.chat_history.append(("user", "Show HR policy"))
                st.session_state.chat_history.append(("bot", response['answer']))
        
        with col2:
            if st.button("🔍 Check My Risk"):
                response = chatbot.process_query(selected_user, "Why was it blocked?")
                st.session_state.chat_history.append(("user", "Check my risk level"))
                st.session_state.chat_history.append(("bot", response['answer']))
        
        with col3:
            if st.button("📤 Export Finance Doc"):
                response = chatbot.process_query(selected_user, "Can I export FIN-2025-001?")
                st.session_state.chat_history.append(("user", "Can I export FIN-2025-001?"))
                st.session_state.chat_history.append(("bot", response['answer']))
        
        # Chat interface
        st.subheader("💬 Chat with Security Assistant")
        
        # Display chat history
        for sender, message in st.session_state.chat_history[-10:]:
            if sender == "user":
                st.markdown(f"""
                <div class="chat-message user-message">
                    <strong>👤 You:</strong><br>{message}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="chat-message bot-message">
                    <strong>🤖 Assistant:</strong><br>{message}
                </div>
                """, unsafe_allow_html=True)
        
        # Chat input
        with st.form("chat_form", clear_on_submit=True):
            user_input = st.text_input("Type your security question:", 
                                     placeholder="e.g., Can I share SB-2025-12 with operations team?")
            target = st.text_input("Target (optional):", placeholder="e.g., operations_team, external_email")
            submitted = st.form_submit_button("Send 📤")
        
        if submitted and user_input:
            st.session_state.chat_history.append(("user", user_input))
            response = chatbot.process_query(selected_user, user_input, target=target or None)
            st.session_state.chat_history.append(("bot", response['answer']))
            st.rerun()
        
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()
    
    # =============================================================================
    # RISK ANALYSIS PAGE
    # =============================================================================
    elif page == "📊 Risk Analysis":
        st.header("📊 Risk Analysis")
        
        # User risk comparison
        st.subheader("👥 User Risk Comparison")
        user_risks = []
        for user in sorted(users):
            risk_score, reasons = risk_engine.calculate_risk_score(user)
            user_risks.append({
                'User': user,
                'Risk Score': risk_score,
                'Primary Risk': reasons[0] if reasons else 'No risks',
                'Risk Count': len([r for r in reasons if 'No risk' not in r])
            })
        
        # Risk chart
        if user_risks:
            users_list = [ur['User'] for ur in user_risks]
            scores = [ur['Risk Score'] for ur in user_risks]
            
            fig = px.bar(x=users_list, y=scores, title='User Risk Scores',
                        color=scores, color_continuous_scale='RdYlGn_r')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # Risk table
            for ur in user_risks:
                col1, col2, col3 = st.columns([2, 1, 3])
                with col1:
                    st.write(f"**{ur['User']}**")
                with col2:
                    score = ur['Risk Score']
                    color = "🔴" if score >= 70 else "🟡" if score >= 30 else "🟢"
                    st.write(f"{color} {score:.0f}")
                with col3:
                    st.write(ur['Primary Risk'])
        
        # Department analysis
        st.subheader("🏢 Department Activity")
        dept_data = {}
        for event in events[-500:]:  # Last 500 events
            dept = event.department
            if dept not in dept_data:
                dept_data[dept] = {'events': 0, 'users': set(), 'exports': 0}
            dept_data[dept]['events'] += 1
            dept_data[dept]['users'].add(event.user_id)
            if event.action == 'export':
                dept_data[dept]['exports'] += 1
        
        if dept_data:
            depts = list(dept_data.keys())
            event_counts = [dept_data[d]['events'] for d in depts]
            
            fig = px.pie(values=event_counts, names=depts, title='Activity by Department')
            st.plotly_chart(fig, use_container_width=True)

if __name__ == "__main__":
    main()