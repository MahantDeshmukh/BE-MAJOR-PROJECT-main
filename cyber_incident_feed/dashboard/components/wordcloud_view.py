"""
Word cloud component for visualizing common keywords in cyber incidents
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
from wordcloud import WordCloud
from collections import Counter
from datetime import datetime
import re
import logging
import sys
import os

# Import from parent directories  
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from database.db_setup import db_manager
from config import VIZ_CONFIG

logger = logging.getLogger(__name__)

def render_wordcloud():
    """Render the word cloud visualization page"""
    st.markdown("# ☁️ Keyword Analysis & Word Clouds")
    st.markdown("Visualize the most common keywords and terms in cybersecurity incidents")
    
    # UI Controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        analysis_period = st.selectbox(
            "Analysis Period",
            [7, 14, 30, 60],
            index=1,
            format_func=lambda x: f"Last {x} days"
        )
    
    with col2:
        filter_type = st.selectbox(
            "Incident Filter",
            ["All Incidents", "India-related Only", "High/Critical Severity"]
        )
    
    with col3:
        word_source = st.selectbox(
            "Text Source",
            ["Titles + Descriptions", "Titles Only", "Keywords Only"]
        )
    
    try:
        # Get incidents from database
        incidents = db_manager.get_recent_incidents(
            limit=500, 
            days=analysis_period, 
            india_only=(filter_type == "India-related Only")
        )
        
        if not incidents:
            st.warning("No incidents found for the selected criteria.")
            return
        
        # Apply severity filter
        if filter_type == "High/Critical Severity":
            incidents = [i for i in incidents if i.severity in ['High', 'Critical']]
        
        if not incidents:
            st.warning("No incidents match the severity filter.")
            return
        
        st.success(f"Analyzing {len(incidents)} incidents from the last {analysis_period} days")
        
        # Extract text data
        text_data = extract_text_from_incidents(incidents, word_source)
        if not text_data:
            st.warning("No text data available for analysis.")
            return
        
        # --- WORD CLOUD VISUALIZATION ---
        st.markdown("## ☁️ Word Cloud Visualizations")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔤 General Keywords")
            general_wordcloud = generate_wordcloud(text_data, exclude_common=True)
            if general_wordcloud:
                fig_general = create_wordcloud_plot(general_wordcloud, "General Keywords")
                st.pyplot(fig_general, use_container_width=True)
        
        with col2:
            st.markdown("### 🔒 Cybersecurity Terms")
            cyber_wordcloud = generate_cyber_wordcloud(text_data)
            if cyber_wordcloud:
                fig_cyber = create_wordcloud_plot(cyber_wordcloud, "Cybersecurity Terms", colormap='Reds')
                st.pyplot(fig_cyber, use_container_width=True)
        
        # --- KEYWORD FREQUENCY ANALYSIS ---
        st.markdown("## 📊 Keyword Frequency Analysis")
        all_keywords = extract_keywords_from_incidents(incidents)
        keyword_counts = Counter(all_keywords)
        
        if keyword_counts:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 🔝 Top Keywords")
                top_keywords = keyword_counts.most_common(20)
                keyword_df = pd.DataFrame(top_keywords, columns=['Keyword', 'Frequency'])
                
                fig_bar = px.bar(
                    keyword_df,
                    x='Frequency',
                    y='Keyword',
                    orientation='h',
                    title='Top 20 Keywords by Frequency',
                    color='Frequency',
                    color_continuous_scale='Blues'
                )
                fig_bar.update_layout(height=600)
                fig_bar.update_yaxes(categoryorder='total ascending')
                st.plotly_chart(fig_bar, use_container_width=True)
            
            with col2:
                st.markdown("### 📈 Keyword Trends")
                keyword_trends = analyze_keyword_trends(incidents, top_keywords[:10])
                
                if keyword_trends:
                    trend_df = pd.DataFrame(keyword_trends)
                    fig_trend = px.line(
                        trend_df,
                        x='Date',
                        y='Count',
                        color='Keyword',
                        title='Top Keywords Trend Over Time',
                        color_discrete_sequence=VIZ_CONFIG['color_palette']
                    )
                    fig_trend.update_layout(height=600)
                    st.plotly_chart(fig_trend, use_container_width=True)
                else:
                    st.info("Insufficient data for trend analysis.")
        
        # --- CATEGORY ANALYSIS ---
        st.markdown("## 🏷️ Category-Specific Keyword Analysis")
        categories = list(set(i.category for i in incidents if i.category))
        
        if categories:
            selected_categories = st.multiselect(
                "Select Categories to Compare",
                categories,
                default=categories[:3] if len(categories) >= 3 else categories
            )
            
            if selected_categories:
                category_keywords = {}
                for category in selected_categories:
                    category_incidents = [i for i in incidents if i.category == category]
                    category_text = extract_text_from_incidents(category_incidents, "Titles + Descriptions")
                    category_keywords[category] = extract_keywords_from_text(category_text)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    comparison_data = []
                    for category, keywords in category_keywords.items():
                        keyword_counts = Counter(keywords)
                        for keyword, count in keyword_counts.most_common(10):
                            comparison_data.append({
                                'Category': category,
                                'Keyword': keyword,
                                'Count': count
                            })
                    
                    if comparison_data:
                        comp_df = pd.DataFrame(comparison_data)
                        fig_cat_bar = px.bar(
                            comp_df,
                            x='Count',
                            y='Keyword',
                            color='Category',
                            orientation='h',
                            title='Top Keywords by Category',
                            barmode='group'
                        )
                        fig_cat_bar.update_layout(height=500)
                        st.plotly_chart(fig_cat_bar, use_container_width=True)
                
                with col2:
                    unique_keywords = {}
                    all_category_keywords = set()
                    
                    for category, keywords in category_keywords.items():
                        all_category_keywords.update(keywords)
                    
                    for category, keywords in category_keywords.items():
                        other_keywords = set()
                        for other_cat, other_kw in category_keywords.items():
                            if other_cat != category:
                                other_keywords.update(other_kw)
                        unique = set(keywords) - other_keywords
                        unique_keywords[category] = len(unique)
                    
                    unique_df = pd.DataFrame(
                        list(unique_keywords.items()),
                        columns=['Category', 'Unique_Keywords']
                    )
                    fig_pie = px.pie(
                        unique_df,
                        values='Unique_Keywords',
                        names='Category',
                        title='Unique Keywords Distribution by Category'
                    )
                    fig_pie.update_layout(height=500)
                    st.plotly_chart(fig_pie, use_container_width=True)
        
        # --- SEVERITY ANALYSIS ---
        st.markdown("## ⚠️ Severity-Based Keyword Analysis")
        severity_keywords = {}
        severities = ['Critical', 'High', 'Medium', 'Low']
        
        for severity in severities:
            severity_incidents = [i for i in incidents if i.severity == severity]
            if severity_incidents:
                severity_text = extract_text_from_incidents(severity_incidents, "Titles + Descriptions")
                severity_keywords[severity] = Counter(extract_keywords_from_text(severity_text))
        
        if severity_keywords:
            severity_data = []
            for severity, keyword_counts in severity_keywords.items():
                for keyword, count in keyword_counts.most_common(15):
                    severity_data.append({
                        'Severity': severity,
                        'Keyword': keyword,
                        'Count': count,
                        'Normalized_Count': count / len([i for i in incidents if i.severity == severity])
                    })
            
            if severity_data:
                sev_df = pd.DataFrame(severity_data)
                heatmap_data = sev_df.pivot(index='Keyword', columns='Severity', values='Normalized_Count').fillna(0)
                fig_heatmap = px.imshow(
                    heatmap_data,
                    title='Keyword Frequency Heatmap by Severity',
                    color_continuous_scale='Reds',
                    aspect='auto'
                )
                fig_heatmap.update_layout(height=600)
                st.plotly_chart(fig_heatmap, use_container_width=True)
        
        # --- EXPORT SECTION ---
        st.markdown("## 📥 Export Keyword Data")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Export Keyword Frequencies"):
                export_data = [{'Keyword': k, 'Frequency': c} for k, c in keyword_counts.most_common()]
                export_df = pd.DataFrame(export_data)
                csv = export_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Keywords CSV",
                    data=csv,
                    file_name=f"keyword_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("🔍 Export Detailed Analysis"):
                detailed_data = []
                for incident in incidents:
                    incident_keywords = incident.keywords if isinstance(incident.keywords, list) else []
                    detailed_data.append({
                        'Date': incident.incident_date.strftime('%Y-%m-%d') if incident.incident_date else '',
                        'Title': incident.title,
                        'Category': incident.category or '',
                        'Severity': incident.severity or '',
                        'Keywords': ', '.join(incident_keywords)
                    })
                detailed_df = pd.DataFrame(detailed_data)
                csv = detailed_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Detailed CSV",
                    data=csv,
                    file_name=f"detailed_keyword_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        # --- INSIGHTS SECTION ---
        st.markdown("## 💡 Keyword Insights")
        insights = []
        
        if keyword_counts:
            top_keyword = keyword_counts.most_common(1)[0]
            insights.append(f"🔝 **Most Frequent Keyword:** '{top_keyword[0]}' appears {top_keyword[1]} times")
        
        cyber_terms = ['ransomware', 'phishing', 'malware', 'ddos', 'breach', 'vulnerability']
        cyber_mentions = sum(keyword_counts.get(term, 0) for term in cyber_terms)
        if cyber_mentions > 0:
            insights.append(f"🔒 **Cybersecurity Focus:** {cyber_mentions} mentions of core security terms")
        
        india_terms = ['india', 'indian', 'delhi', 'mumbai', 'bangalore', 'aadhaar']
        india_mentions = sum(keyword_counts.get(term, 0) for term in india_terms)
        if india_mentions > 0:
            insights.append(f"🇮🇳 **India Context:** {india_mentions} mentions of India-related terms")
        
        for insight in insights:
            st.markdown(insight)
    
    except Exception as e:
        st.error(f"Failed to generate word cloud analysis: {e}")
        logger.error(f"Word cloud error: {e}")
        with st.expander("Error Details"):
            st.exception(e)

# --- Helper Functions ---
def extract_text_from_incidents(incidents, source_type):
    text_parts = []
    for incident in incidents:
        if source_type == "Titles Only":
            text_parts.append(incident.title or "")
        elif source_type == "Keywords Only" and isinstance(incident.keywords, list):
            text_parts.extend(incident.keywords)
        else:
            text_parts.append(f"{incident.title or ''} {incident.description or ''}")
    return " ".join(text_parts)

def generate_wordcloud(text_data, exclude_common=True):
    if not text_data:
        return None
    stopwords = set([
        'the','and','or','but','in','on','at','to','for','of','with','by','from','up','about','into','through','during',
        'before','after','above','below','between','among','throughout','despite','towards','upon','concerning','a','an',
        'as','are','was','were','been','be','have','has','had','do','does','did','will','would','could','should','may',
        'might','must','shall','can','is','it','this','that','these','those','i','me','my','myself','we','our','ours',
        'ourselves','you','your','yours','yourself','yourselves','he','him','his','himself','she','her','hers','herself',
        'they','them','their','theirs','themselves','what','which','who','whom','whose','when','where','why','how','all',
        'any','both','each','few','more','most','other','some','such','no','nor','not','only','own','same','so','than',
        'too','very','just','now'
    ])
    try:
        return WordCloud(
            width=800, height=400, background_color='white',
            stopwords=stopwords if exclude_common else None,
            max_words=100, relative_scaling=0.5, colormap='viridis'
        ).generate(text_data)
    except Exception as e:
        logger.error(f"WordCloud generation failed: {e}")
        return None

def generate_cyber_wordcloud(text_data):
    if not text_data:
        return None
    cyber_terms = re.findall(
        r'\b(?:cyber|security|attack|breach|malware|ransomware|phishing|ddos|vulnerability|exploit|hacking|hack|hacker|trojan|virus|spyware|botnet|firewall|encryption|authentication|authorization|penetration|intrusion|incident|threat|risk|data|information|network|system|server|database|password|credential|social engineering|zero day|apt|injection|sql|privilege escalation)\b',
        text_data.lower()
    )
    if not cyber_terms:
        return None
    try:
        return WordCloud(width=800, height=400, background_color='white', max_words=80, relative_scaling=0.5, colormap='Reds').generate(' '.join(cyber_terms))
    except Exception as e:
        logger.error(f"Cyber WordCloud generation failed: {e}")
        return None

def create_wordcloud_plot(wordcloud, title, colormap='viridis'):
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.imshow(wordcloud, interpolation='bilinear')
    ax.set_title(title, fontsize=16, fontweight='bold')
    ax.axis('off')
    return fig

def extract_keywords_from_incidents(incidents):
    all_keywords = []
    for incident in incidents:
        if isinstance(incident.keywords, list):
            all_keywords.extend(incident.keywords)
        text = f"{incident.title or ''} {incident.description or ''}"
        all_keywords.extend(extract_keywords_from_text(text))
    return all_keywords

def extract_keywords_from_text(text):
    if not text:
        return []
    text_lower = text.lower()
    important_terms = [
        'ransomware','phishing','malware','ddos','vulnerability','exploit','hacking','breach','attack','cybersecurity',
        'security','threat','india','indian','delhi','mumbai','bangalore','hyderabad','chennai','aadhaar','government',
        'banking','financial','healthcare','education','apt','trojan','virus','spyware','botnet','firewall','encryption',
        'authentication','network','database','server','data','information','password','credential','injection','zero-day','social engineering'
    ]
    keywords = []
    for term in important_terms:
        if term in text_lower:
            keywords.extend([term] * text_lower.count(term))
    return keywords

def analyze_keyword_trends(incidents, top_keywords):
    trend_data = []
    date_groups = {}
    for incident in incidents:
        if incident.incident_date:
            date_key = incident.incident_date.date()
            date_groups.setdefault(date_key, []).append(incident)
    for date, date_incidents in date_groups.items():
        date_text = extract_text_from_incidents(date_incidents, "Titles + Descriptions")
        date_keywords = extract_keywords_from_text(date_text)
        keyword_counts = Counter(date_keywords)
        for keyword, _ in top_keywords:
            trend_data.append({'Date': date, 'Keyword': keyword, 'Count': keyword_counts.get(keyword, 0)})
    return trend_data
