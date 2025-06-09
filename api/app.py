import re
import os
from flask import Flask, request, jsonify, make_response, send_file, Response
from flask_cors import CORS
import sys
from dotenv import load_dotenv
import json
from jinja2 import Template
import pdfkit
import datetime
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import chromadb
from chromadb.utils import embedding_functions
import uuid # For generating unique report IDs
from collections import Counter # Add this import at the top of the file if not already present
import yaml # For parsing YAML files
import glob # For file pattern matching
import requests
import time
import hashlib
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io

# Load environment variables from .env file
load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the required SigmAIQ components
from langchain_openai import OpenAIEmbeddings
from langchain_openai import ChatOpenAI
from sigmaiq.llm.base import SigmaLLM
from sigmaiq.llm.toolkits.base import create_sigma_agent
from sigmaiq import SigmAIQBackend

# Get API key from environment or config
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# Get LLM model names from environment variables, with defaults
SOC_REPORT_MODEL_NAME = os.environ.get("SOC_REPORT_MODEL_NAME", "gpt-4-turbo-preview")
RAG_QUERY_MODEL_NAME = os.environ.get("RAG_QUERY_MODEL_NAME", "gpt-3.5-turbo") # Defaulting RAG to a potentially faster/cheaper model

print(f"Using SOC Report Model: {SOC_REPORT_MODEL_NAME}")
print(f"Using RAG Query Model: {RAG_QUERY_MODEL_NAME}")

# --- Globals for Enhanced RAG ---
_cached_report_data = {
    "report_id": None,
    "chunks": [],
    "embeddings": None
}
_report_embedding_model = None
# --- End Globals for Enhanced RAG ---

# --- Globals for ChromaDB SOC Report Store ---
CHROMA_DB_PATH = "./chroma_db_store"
SOC_REPORTS_COLLECTION_NAME = "soc_reports_collection"
chroma_client = None
soc_reports_collection = None
# --- End Globals for ChromaDB SOC Report Store ---

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins="*", supports_credentials=False)  # Allow all origins for development

# --- WKHTMLTOPDF CONFIGURATION ---
# IMPORTANT: VERIFY THIS PATH IS CORRECT FOR YOUR WKHTMLTOPDF INSTALLATION
# If wkhtmltopdf was added to system PATH during installation and is findable,
# you might be able to comment out path_wkhtmltopdf and config, and remove config from from_string call.
path_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe' # *** ENSURE THIS IS THE CORRECT PATH ***

# Check if the specified wkhtmltopdf path actually exists
if os.path.exists(path_wkhtmltopdf):
    print(f"WKHTMLTOPDF: Found executable at configured path: {path_wkhtmltopdf}")
    config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
else:
    print(f"WKHTMLTOPDF ERROR: Executable NOT FOUND at configured path: {path_wkhtmltopdf}")
    print("WKHTMLTOPDF: pdfkit will attempt to find wkhtmltopdf in system PATH.")
    config = None # Explicitly set to None if path is invalid, so pdfkit tries PATH
# --- END WKHTMLTOPDF CONFIGURATION ---

# Initialize SigmaLLM, load vector database, and create agent at startup
# These objects will be reused for all requests
sigma_llm = None
sigma_agent_executor = None
backend = None

def initialize_sigma():
    global sigma_llm, sigma_agent_executor, backend
    global chroma_client, soc_reports_collection, _report_embedding_model, OPENAI_API_KEY
    
    print("Initializing SigmaIQ components...")
    # Use the environment API key for initialization
    api_key = OPENAI_API_KEY
    
    if not api_key:
        print("WARNING: No API key found in environment variables")
        return
    
    try:
        # Initialize SigmaLLM
        sigma_llm = SigmaLLM(embedding_model=OpenAIEmbeddings(model="text-embedding-3-large", api_key=api_key))
        
        # Load or create Sigma VectorDB
        try:
            print("Loading Sigma VectorDB...")
            sigma_llm.load_sigma_vectordb()
        except Exception as e:
            print(f"Error loading vector DB: {e}")
            print("Creating new Sigma VectorDB")
            sigma_llm.create_sigma_vectordb(save=True)
        
        # Create Sigma Agent Executor
        print("Creating Sigma Agent Executor...")
        sigma_agent_executor = create_sigma_agent(sigma_vectorstore=sigma_llm.sigmadb)
        
        # Create Backend for translation to EL query
        print("Creating EL query backend...")
        pipelines = ["ecs_windows", "ecs_zeek_beats"]
        backend = SigmAIQBackend(backend="elasticsearch", processing_pipeline=pipelines).create_backend()
        
        print("SigmaIQ components initialized successfully!")
    except Exception as e:
        print(f"Error initializing SigmaIQ components: {e}")

    # --- Initialize ChromaDB --- 
    try:
        print(f"Initializing ChromaDB client with path: {CHROMA_DB_PATH}")
        chroma_client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        
        openai_ef = None
        # Define the model name we intend to use for report embeddings consistently
        report_embedding_model_name = "text-embedding-3-small" 

        if OPENAI_API_KEY:
            # Initialize our primary report embedding model instance if not already done
            # This function (get_report_embedding_model) uses report_embedding_model_name internally if we align them
            _ = get_report_embedding_model(OPENAI_API_KEY) # Ensures _report_embedding_model is initialized with the chosen name
            
            openai_ef = embedding_functions.OpenAIEmbeddingFunction(
                api_key=OPENAI_API_KEY,
                model_name=report_embedding_model_name # Pass the model name string directly
            )
            print(f"Using OpenAIEmbeddingFunction for ChromaDB collection with model: {report_embedding_model_name}")
        else:
            print("Warning: OPENAI_API_KEY not found. ChromaDB collection might have issues if embeddings are not explicitly provided during 'add'.")

        print(f"Attempting to get or create ChromaDB collection: {SOC_REPORTS_COLLECTION_NAME}")
        soc_reports_collection = chroma_client.get_or_create_collection(
            name=SOC_REPORTS_COLLECTION_NAME,
            embedding_function=openai_ef
        )
        print(f"Successfully connected to ChromaDB collection: {SOC_REPORTS_COLLECTION_NAME}")
        print(f"Collection current document count: {soc_reports_collection.count()}")

    except Exception as e:
        print(f"Error initializing ChromaDB: {e}")
        chroma_client = None
        soc_reports_collection = None

# LLM API Configuration (Example for OpenAI)
# openai.api_key = os.environ.get("OPENAI_API_KEY") # Recommended to use environment variables

# This is the system architecture string you provided.
# You could also pass this from the frontend if it might change,
# but for now, having it defined where the LLM call is made is fine.
SYSTEM_ARCHITECTURE_PROMPT_SECTION = """
System Architecture Context:
The system includes the following main components: The Internet is connected to a WAF (Web Application Firewall), 
where the WAF protects the Web Server from attacks such as SQL Injection, XSS, RCE, etc., by filtering and 
blocking malicious traffic. Valid traffic is then routed through a Router integrated with IDS (Snort), 
which helps monitor and detect abnormal behavior in the internal network. Snort sends logs to the ELK SIEM 
system for analysis. The ELK SIEM is integrated with MISP, a component specializing in collecting IoCs 
(Indicators of Compromise) from threat intelligence sources and converting them into Sigma rules to detect 
threats in log data. Clients (computers) and the web server within the system are sources of event generation.

**Web Server Details**: The environment includes a web server that may be running DVWA (Damn Vulnerable Web Application), 
which is a PHP/MySQL web application designed to be vulnerable to common web attacks. DVWA includes vulnerabilities 
such as SQL Injection, XSS, Command Injection, File Upload, File Inclusion, CSRF, and more. However, only mention 
DVWA in your analysis if the alert data contains clear evidence of web application attacks, such as HTTP requests, 
URL patterns containing '/dvwa/', '/vulnerabilities/', or other web-specific indicators.
"""

# --- RAG Enhancement Helper Functions ---

def get_report_embedding_model(api_key_to_use: str):
    global _report_embedding_model
    # Ensure consistency with the model name used for ChromaDB's EF
    report_model_name_for_embeddings = "text-embedding-3-small" 
    if _report_embedding_model is None or _report_embedding_model.openai_api_key != api_key_to_use or _report_embedding_model.model != report_model_name_for_embeddings:
        _report_embedding_model = OpenAIEmbeddings(model=report_model_name_for_embeddings, api_key=api_key_to_use)
        print(f"Initialized/Re-initialized report embedding model: {report_model_name_for_embeddings}")
    return _report_embedding_model

def chunk_soc_report(report_data: dict) -> list[dict]:
    """
    Breaks down the SOC report (parsed JSON) into meaningful text chunks.
    Each chunk is now a dictionary with 'text' and 'source_section'.
    Technical Analysis is chunked by paragraph.
    """
    chunks = []
    if not isinstance(report_data, dict):
        print("Warning: report_data for chunking is not a dictionary. Treating as single chunk.")
        # Ensure even this fallback produces a string for 'text'
        chunks.append({'text': str(report_data), 'source_section': 'Unknown Section'})
        return chunks

    # Event Summary
    if report_data.get("eventSummary"):
        chunks.append({'text': str(report_data['eventSummary']), 'source_section': 'Event Summary'}) # Ensure string

    # Technical Analysis - chunk by paragraph
    if report_data.get("technicalAnalysis"):
        technical_analysis_text = str(report_data['technicalAnalysis']) # Ensure string before split
        paragraphs = re.split(r'\\n\\s*\\n+', technical_analysis_text.strip())
        for i, para in enumerate(paragraphs):
            if para.strip():
                chunks.append({'text': para.strip(), 'source_section': f'Technical Analysis - Paragraph {i+1}'})
    
    # Defensive Rules
    if report_data.get("defensiveRules") and isinstance(report_data["defensiveRules"], dict):
        if report_data["defensiveRules"].get("description"):
            chunks.append({
                'text': str(report_data["defensiveRules"]['description']),  # Ensure string
                'source_section': 'Defensive Rules - Summary'
            })
        if isinstance(report_data["defensiveRules"].get("rules"), list):
            for i, rule in enumerate(report_data["defensiveRules"]["rules"]):
                rule_text_parts = []
                if rule.get('type'):
                    rule_text_parts.append(f"Type: {str(rule['type'])}") # Ensure string
                if rule.get('content'):
                    rule_text_parts.append(f"Content: {str(rule['content'])}") # Ensure string
                if rule.get('description'):
                    rule_text_parts.append(f"Description: {str(rule['description'])}") # Ensure string
                
                full_rule_text = ", ".join(rule_text_parts)
                chunks.append({'text': full_rule_text, 'source_section': f'Defensive Rule {i+1}'})
    
    # System Remediation
    if report_data.get("systemRemediation"):
        chunks.append({'text': str(report_data['systemRemediation']), 'source_section': 'System Remediation'}) # Ensure string
    
    # MITRE ATT&CK Table
    if report_data.get("mitreAttackTable") and isinstance(report_data["mitreAttackTable"], list):
        # Store the MITRE ATT&CK table as JSON string for easy parsing later
        chunks.append({
            'text': json.dumps(report_data["mitreAttackTable"]), 
            'source_section': 'mitreAttackTable'
        })
    
    if not chunks and report_data: 
        chunks.append({'text': json.dumps(report_data), 'source_section': 'Full Report Fallback'}) # json.dumps is good

    print(f"Report chunked into {len(chunks)} parts, now with source_section info.")
    # Final check to ensure all chunk texts are strings, though the above should cover it.
    # This could be an assertion or a more robust conversion if needed.
    for chunk_item in chunks:
        if not isinstance(chunk_item.get('text'), str):
            print(f"Warning: Chunk text for section '{chunk_item.get('source_section')}' is not a string. Attempting conversion. Original type: {type(chunk_item.get('text'))}")
            chunk_item['text'] = str(chunk_item.get('text', '')) # Fallback to empty string if text is missing

    return [chunk for chunk in chunks if chunk.get('text')] # Ensure chunk has non-empty text

def generate_and_cache_report_embeddings(report_id: str, report_context_string: str, api_key: str) -> bool:
    global _cached_report_data
    if _cached_report_data.get("report_id") == report_id and _cached_report_data.get("embeddings") is not None:
        print(f"Embeddings for report ID {report_id} already cached.")
        return True
    try:
        report_data_json = json.loads(report_context_string)
    except json.JSONDecodeError:
        print("Error: reportContextString is not valid JSON. Using as single chunk.")
        report_data_json = {"full_report_text": report_context_string}
    chunks = chunk_soc_report(report_data_json)
    if not chunks:
        print("No chunks generated from report. Cannot create embeddings.")
        _cached_report_data = {"report_id": report_id, "chunks": [], "embeddings": None}
        return False
    embedding_model = get_report_embedding_model(api_key)
    try:
        embeddings = embedding_model.embed_documents(chunks)
        _cached_report_data["report_id"] = report_id
        _cached_report_data["chunks"] = chunks
        _cached_report_data["embeddings"] = np.array(embeddings)
        print(f"Successfully generated and cached {len(embeddings)} embeddings for report ID {report_id}.")
        return True
    except Exception as e:
        print(f"Error generating report embeddings: {e}")
        _cached_report_data = {"report_id": report_id, "chunks": chunks, "embeddings": None}
        return False

def get_relevant_chunks(user_query: str, api_key: str, top_n: int = 3) -> list[str]:
    global _cached_report_data
    if _cached_report_data.get("embeddings") is None or not _cached_report_data.get("chunks"):
        print("No cached report embeddings or chunks available to retrieve from.")
        return []
    embedding_model = get_report_embedding_model(api_key)
    try:
        query_embedding = embedding_model.embed_query(user_query)
    except Exception as e:
        print(f"Error embedding user query: {e}")
        return []
    query_embedding_np = np.array(query_embedding).reshape(1, -1)
    report_embeddings_np = _cached_report_data["embeddings"]
    similarities = cosine_similarity(query_embedding_np, report_embeddings_np)[0]
    num_available_chunks = len(_cached_report_data["chunks"])
    actual_top_n = min(top_n, num_available_chunks)
    top_indices = np.argsort(similarities)[-actual_top_n:][::-1]
    relevant_chunks = [_cached_report_data["chunks"][i] for i in top_indices]
    print(f"Retrieved {len(relevant_chunks)} relevant chunks for the query.")
    return relevant_chunks

# --- End RAG Enhancement Helper Functions ---

# Regex patterns for metadata extraction
MITRE_TTP_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# --- ChromaDB SOC Report Storage Functions ---
def process_and_store_report_in_chroma(report_id: str, report_json: dict, alert_data_source: any):
    global soc_reports_collection, OPENAI_API_KEY

    if soc_reports_collection is None:
        print("Error: ChromaDB collection for SOC reports is not initialized. Cannot store report.")
        return

    if not OPENAI_API_KEY:
        print("Error: OPENAI_API_KEY is not available. Cannot generate embeddings for ChromaDB storage.")
        return

    print(f"Processing report ID {report_id} for ChromaDB storage.")

    try:
        # 1. Chunk the report - chunk_soc_report now returns list of dicts: {'text': ..., 'source_section': ...}
        report_chunk_objects = chunk_soc_report(report_json) 
        if not report_chunk_objects:
            print(f"Report ID {report_id} resulted in no chunks. Skipping storage.")
            return

        report_chunks_texts = [chunk['text'] for chunk in report_chunk_objects]
        
        # 2. Generate embeddings for these chunks
        embedding_model = get_report_embedding_model(OPENAI_API_KEY)
        report_chunk_embeddings = embedding_model.embed_documents(report_chunks_texts)

        # 3. Prepare metadata for each chunk
        metadatas = []
        doc_ids = [] 
        # Store timestamp as Unix epoch integer for numerical range queries
        current_timestamp_unix = int(datetime.datetime.utcnow().timestamp())
        source_identifier = "unknown_source"
        if isinstance(alert_data_source, list) and alert_data_source:
            first_alert = alert_data_source[0]
            if isinstance(first_alert, dict):
                source_identifier = first_alert.get('_id', first_alert.get('id', f"alert_list_item_0_{report_id}"))
        elif isinstance(alert_data_source, dict):
            source_identifier = alert_data_source.get('_id', alert_data_source.get('id', f"alert_dict_{report_id}"))
        event_summary_preview = report_json.get("eventSummary", "")[:200]

        for i, chunk_obj in enumerate(report_chunk_objects):
            chunk_id = f"{report_id}_chunk_{i}"
            doc_ids.append(chunk_id)
            
            chunk_text = chunk_obj['text']
            source_section_name = chunk_obj['source_section']
            
            current_chunk_metadata = {
                "report_id": report_id,
                "chunk_index": i,
                "source_section": source_section_name,
                "timestamp_unix": current_timestamp_unix, # Changed from timestamp_utc to timestamp_unix
                "source_alert_id": str(source_identifier),
                "event_summary_preview": event_summary_preview,
            }

            # Extract TTPs and CVEs if the chunk is from Technical Analysis
            if source_section_name.startswith("Technical Analysis"):
                try:
                    # Ensure chunk_text is treated as a string for findall, then join list to string
                    mitre_ttps_list = list(set(MITRE_TTP_PATTERN.findall(str(chunk_text)))) 
                    current_chunk_metadata["mitre_ttps"] = ",".join(mitre_ttps_list) if mitre_ttps_list else ""
                except Exception as e_ttp:
                    print(f"Warning: Could not extract TTPs for chunk {chunk_id}: {e_ttp}")
                    current_chunk_metadata["mitre_ttps"] = ""
                
                try:
                    # Ensure chunk_text is treated as a string for findall, then join list to string
                    cves_list = list(set(CVE_PATTERN.findall(str(chunk_text))))
                    current_chunk_metadata["cves"] = ",".join(cves_list) if cves_list else ""
                except Exception as e_cve:
                    print(f"Warning: Could not extract CVEs for chunk {chunk_id}: {e_cve}")
                    current_chunk_metadata["cves"] = ""
            
            metadatas.append(current_chunk_metadata)
        
        # 4. Add to ChromaDB collection
        # Ensure soc_reports_collection is not None again, just in case.
        if soc_reports_collection is not None:
            soc_reports_collection.add(
                ids=doc_ids,
                embeddings=report_chunk_embeddings,
                documents=report_chunks_texts,
                metadatas=metadatas
            )
            print(f"Successfully stored {len(doc_ids)} chunks for report ID {report_id} in ChromaDB.")
            print(f"Collection document count now: {soc_reports_collection.count()}")
        else:
            print("Critical Error: soc_reports_collection became None during report processing.")

    except Exception as e:
        print(f"Error processing and storing report ID {report_id} in ChromaDB: {e}")
        import traceback
        traceback.print_exc()
# --- End ChromaDB SOC Report Storage Functions ---

def construct_llm_prompt(alert_data_json_str: str, system_architecture_desc: str) -> str:
    """
    Constructs a detailed prompt for the LLM to generate the SOC report.
    """
    prompt = f"""
You are a Senior SOC Analyst tasked with analyzing the provided SIEM alert data and system architecture to generate a comprehensive incident report.

The report MUST be in JSON format with the following exact top-level keys: "eventSummary", "technicalAnalysis", "defensiveRules", "systemRemediation", "mitreAttackTable".

- "eventSummary": (String) Provide a comprehensive yet digestible overview of the incident in English, suitable for an executive summary. This summary must synthesize the key findings from the detailed technical analysis that will follow. It should clearly articulate:
    1.  What happened: A clear description of the security event(s).
    2.  Suspected Threat Actor: An assessment of the likely threat actor type (e.g., script kiddie, hacktivist, organized crime, state-sponsored/APT). Justify this assessment briefly based on observed TTPs or targets.
    3.  Probable Motivation: The most probable motivation or primary objective behind the attack (e.g., data theft of specific types, financial extortion, service disruption, intellectual property theft, espionage, establishing persistence for future operations, simple vandalism). Explain the reasoning for this assessment. If motivation is unclear, explicitly state so and why.
    4.  Key Impact: Briefly state the actual or potential impact on the organization's assets, operations, or reputation, drawing from the detailed analysis.
    5.  Critical Systems Involved: Mention the primary systems or data that were targeted or affected. 
        **IMPORTANT**: Only mention "DVWA" or "web application" if the alert data contains clear evidence of web application attacks, 
        such as HTTP requests, URLs containing '/dvwa/', '/vulnerabilities/', web-specific payloads, or HTTP-based attack patterns. 
        For network-level attacks (e.g., DDoS, port scans, protocol attacks) that don't target web applications specifically, 
        refer to the affected systems by their actual identifiers (IP addresses, hostnames, network segments) without assuming DVWA involvement.
    Ensure this summary is detailed enough to stand alone in conveying the essence and severity of the incident.
- "technicalAnalysis": (String) Provide an extremely detailed, comprehensive, and in-depth forensic analysis of the provided SIEM alert(s). **Structure your technical analysis into multiple distinct paragraphs, with each paragraph addressing a specific phase of the attack (e.g., based on Lockheed Martin Cyber Kill Chain or MITRE ATT&CK stages), a key observation, or a particular TTP. Separate each paragraph with two newline characters for proper formatting and readability. Use clear topic sentences for each paragraph to enhance readability and logical flow.** Your analysis must follow a clear attack kill chain methodology (e.g., Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact). For each identified stage relevant to the alerts:
    1.  Explain the attacker's specific TTPs (Tactics, Techniques, and Procedures) with high granularity, always relating them to the provided System Architecture Context.
    2.  **CRITICAL REQUIREMENT:** You MUST explicitly map all observed or inferred malicious activities to relevant MITRE ATT&CK technique IDs (e.g., T1071) AND, where applicable, sub-technique IDs (e.g., T1071.001). Present these IDs clearly within your analysis for each relevant TTP. For example: "The attacker utilized Web Protocols (T1071.001) for C2 communication." Ensure accuracy and adherence to the standard MITRE ATT&CK naming and ID conventions.
    3.  Identify all potential attack vectors, initially compromised systems/accounts, and subsequently affected systems.
    4.  Describe the specific forensic artifacts (e.g., log entries, file system changes, network traffic patterns, memory signatures) that would typically be found on affected systems or network devices for each TTP.
    5.  If the analysis reveals the exploitation of a specific, known, and publicly disclosed vulnerability, you MUST cite the relevant CVE identifier(s) (e.g., CVE-2023-12345) associated with that vulnerability. If no specific CVE is identified or applicable, do not invent one.
    6.  If a known vulnerability (with or without a CVE) or a common exploit mechanism is identified, describe a conceptual Proof of Concept (PoC). This PoC should detail how an attacker might try to execute the exploit, including the types of tools, commands, or interactions involved. Focus on the mechanism and steps; do NOT generate full, runnable malicious scripts.
    7.  Thoroughly explain the full potential impact of the attack if successful, considering data confidentiality, integrity, and availability, as well as operational disruption.
    This section must be very extensive, written in clear, professional English, and demonstrate deep cybersecurity expertise. Ensure the analysis is as long and detailed as necessary to cover all these points exhaustively for each alert provided. Leave no stone unturned. Write in a natural, flowing style with proper paragraph breaks for readability.
- "defensiveRules": (Object) This object must contain:
    - "description": (String) A general summary of the defensive rule strategy in English. If ModSecurity rules are not generated because the alerts are not OWASP Top 10 related web attacks, briefly state this.
    - "rules": (Array of Objects) Each object in this array represents a specific rule and MUST have the following keys:
        - "type": (String) The type of rule. Valid values are "snort" or "modsecurity".
        - "content": (String) The actual rule content.
        - "description": (String, optional) A brief description of what the rule does in English.
    Instructions for rule generation:
    1.  ALWAYS generate Snort IDS rules for network-level threats or general suspicious activity.
    2.  Analyze the alerts to determine if they specifically indicate attacks targeting web applications that align with common OWASP Top 10 vulnerabilities (e.g., SQL Injection, XSS, CSRF, Insecure Deserialization, etc.) AND if the provided System Architecture Context indicates the presence of a Web Server and WAF.
    3.  IF AND ONLY IF both conditions in point 2 are met (OWASP Top 10 related web attack AND relevant system architecture), THEN generate appropriate ModSecurity WAF rules.
    4.  For ModSecurity rules targeting web applications, use the following format and examples as guidance:
        - For RCE/Command Injection: SecRule ARGS "@rx (?:;|`|&&|\||\$\(|nc\s|wget\s|curl\s|cat\s|ls\s|id\s|whoami)" "id:800001,phase:2,t:none,deny,log,msg:'RCE Payload Detected in ARGS',logdata:'%{{MATCHED_VAR}}',status:403"
        - For SQL Injection: SecRule ARGS "@rx (?:union.*select|select.*from|insert.*into|delete.*from|update.*set|\\'.*or.*\\'|\\'.*and.*\\')" "id:800002,phase:2,t:none,deny,log,msg:'SQL Injection Payload Detected in ARGS',logdata:'%{{MATCHED_VAR}}',status:403"
        - For XSS: SecRule ARGS "@rx (?:<script|javascript:|onload=|onerror=|alert\(|document\.cookie)" "id:800003,phase:2,t:none,deny,log,msg:'XSS Payload Detected in ARGS',logdata:'%{{MATCHED_VAR}}',status:403"
        - For File Inclusion: SecRule ARGS "@rx (?:\.\./|\.\.\\\\|/etc/passwd|/proc/|php://)" "id:800004,phase:2,t:none,deny,log,msg:'File Inclusion Payload Detected in ARGS',logdata:'%{{MATCHED_VAR}}',status:403"
    5.  Ensure ModSecurity rule IDs start from 800001 onwards to avoid conflicts with OWASP CRS rules, and focus on detecting malicious payload patterns in ARGS.
    6.  If ModSecurity rules are not generated due to the conditions in point 2 not being met, the "rules" array should only contain Snort rules (or be empty if no rules are suitable at all).
    Do NOT generate Sigma rules.
- "systemRemediation": (String) Provide actionable, step-by-step recommendations to contain the threat, eradicate the attacker's presence, recover affected systems, and improve overall security posture based on the incident and the system architecture. Ensure each numbered or bulleted recommendation is on a new line (e.g., using \\n). This section must be in English.
- "mitreAttackTable": (Array of Objects) Create a comprehensive table of all MITRE ATT&CK techniques identified in the technical analysis. Each object in this array MUST have the following keys:
    - "stage": (String) The MITRE ATT&CK tactic/stage (e.g., "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact")
    - "techniqueName": (String) The full name of the MITRE ATT&CK technique (e.g., "PowerShell", "Web Protocols", "System Information Discovery")
    - "techniqueCode": (String) The MITRE ATT&CK technique ID including sub-technique if applicable (e.g., "T1059.001", "T1071.001", "T1082")
    - "description": (String) A brief description of how this technique was observed or inferred in the context of this specific incident
    Instructions for MITRE ATT&CK table:
    1. Only include techniques that are explicitly mentioned or strongly inferred from the technical analysis
    2. Ensure technique codes are accurate and follow official MITRE ATT&CK framework
    3. Order the techniques chronologically based on the attack kill chain when possible
    4. Provide incident-specific descriptions, not generic technique descriptions

The entire output MUST be a single JSON object. Do not include any text or explanations outside of this JSON object.
Ensure all string content within the JSON is in English.
The report should be written in a professional tone suitable for a cybersecurity operations environment.

SIEM Alert Data (JSON format):
{alert_data_json_str}

{system_architecture_desc}

Generate the incident report based on ALL the information provided.
"""
    return prompt

@app.route('/api/generate', methods=['POST'])
def generate_rule():
    global sigma_llm, sigma_agent_executor, backend
    
    data = request.json
    user_input = data.get('prompt', '')
    
    # Get API key from request header if provided
    api_key = request.headers.get('X-API-KEY') or OPENAI_API_KEY
    
    if not user_input:
        return jsonify({"error": "No prompt provided"}), 400
    
    if not api_key:
        return jsonify({"error": "API key is required. Please set it in the settings."}), 401
    
    # If the global objects aren't initialized or the API key changed, initialize them
    if sigma_llm is None or api_key != OPENAI_API_KEY:
        try:
            # Only recreate if API key changed from request header
            if api_key != OPENAI_API_KEY:
                print("Using new API key from request header")
                # Initialize SigmaLLM with the provided API key
                sigma_llm = SigmaLLM(embedding_model=OpenAIEmbeddings(model="text-embedding-3-large", api_key=api_key))
                
                try:
                    sigma_llm.load_sigma_vectordb()
                except Exception as e:
                    print(f"Error loading vector DB: {e}")
                    print("Creating new Sigma VectorDB")
                    sigma_llm.create_sigma_vectordb(save=True)
                
                # Create Sigma Agent Executor
                sigma_agent_executor = create_sigma_agent(sigma_vectorstore=sigma_llm.sigmadb)
                pipelines = ["ecs_windows", "ecs_zeek_beats"]
                # Create Backend for translation to EL query
                backend = SigmAIQBackend(backend="elasticsearch", processing_pipeline=pipelines).create_backend()
            else:
                # Try initialization again with environment API key
                initialize_sigma()
        except Exception as e:
            return jsonify({"error": f"Failed to initialize SigmaIQ components: {str(e)}"}), 500
    
    try:
        if sigma_agent_executor is None:
            return jsonify({"error": "SigmaIQ components not initialized. Please check your API key."}), 500
            
        # Generate Sigma rule using Sigma Agent Executor
        sigma_rule_result = sigma_agent_executor.invoke({"input": user_input})
        raw_output = sigma_rule_result.get("output", "")
        cleaned_rule = extract_yaml_block(raw_output)
        print(cleaned_rule)
        # Translate the Sigma rule to an EL query
        translated_output = backend.translate(cleaned_rule)
        
        return jsonify({
            "sigmaRule": cleaned_rule,
            "eqlQuery": translated_output[0]
        })
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    global sigma_llm, sigma_agent_executor, backend
    status = {
        "status": "ok",
        "sigma_llm_initialized": sigma_llm is not None,
        "sigma_agent_initialized": sigma_agent_executor is not None,
        "backend_initialized": backend is not None
    }
    return jsonify(status), 200

@app.route('/api/generate-soc-report', methods=['POST'])
def generate_soc_report_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No input data provided"}), 400

        alert_data = data.get('alertData') # This is expected to be a list of alert objects
        # system_architecture_from_frontend = data.get('systemArchitecture') # This is the string from frontend
        # We are using the globally defined SYSTEM_ARCHITECTURE_PROMPT_SECTION for consistency in the prompt

        if not alert_data: # No longer strictly needing systemArchitecture from frontend as it's defined globally
            return jsonify({"message": "Missing 'alertData' in request"}), 400

        alert_data_json_string = json.dumps(alert_data, indent=2)
        
        final_prompt = construct_llm_prompt(
            alert_data_json_str=alert_data_json_string,
            system_architecture_desc=SYSTEM_ARCHITECTURE_PROMPT_SECTION 
        )
        
        # --- Actual LLM Call using ChatOpenAI ---
        if not OPENAI_API_KEY:
            # This check is important if API key might not be set
            print("ERROR: OpenAI API key not configured for SOC report generation.")
            return jsonify({"message": "OpenAI API key not configured on the server."}), 500

        print(f"Attempting to generate SOC report with model. Prompt length: {len(final_prompt)} chars.") # For debugging

        try:
            # Initialize ChatOpenAI model
            chat_model = ChatOpenAI(
                api_key=OPENAI_API_KEY,
                model=SOC_REPORT_MODEL_NAME, # Use configured model name
                temperature=0.2, 
                model_kwargs={"response_format": {"type": "json_object"}}
            )
            
            # Invoke the model
            # The prompt already requests JSON, and response_format reinforces this.
            response = chat_model.invoke(final_prompt)
            
            llm_response_content = response.content
            
            # The LLM should directly return a JSON string due to response_format and prompt.
            report_json = json.loads(llm_response_content)

            print("Successfully received and parsed JSON response from LLM for SOC report.")

        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from LLM response: {e}")
            print(f"LLM Raw Response Content:\\n{llm_response_content}")
            return jsonify({"message": f"Error decoding JSON from LLM: {str(e)}. Check server logs for raw response."}), 500
        except Exception as e:
            # This catches errors from the chat_model.invoke call or other unexpected issues
            print(f"Error calling LLM or processing its response: {e}")
            # Consider logging the 'final_prompt' here for debugging failed LLM calls, but be mindful of sensitive data.
            return jsonify({"message": f"Error communicating with LLM: {str(e)}"}), 500
        
        # --- End of LLM Call ---

        # Post-process the report to clean up formatting issues
        report_json = post_process_soc_report(report_json)

        # Ensure the response matches the SocReportResponse structure (optional validation)
        # Example basic validation:
        expected_keys = ["eventSummary", "technicalAnalysis", "defensiveRules", "systemRemediation", "mitreAttackTable"]
        if not all(key in report_json for key in expected_keys):
            print(f"LLM response missing expected keys. Got: {report_json.keys()}")
            return jsonify({"message": "LLM response did not match the expected report structure."}), 500
        
        # Generate a unique ID for this report
        new_report_id = str(uuid.uuid4())

        # Asynchronously process and store the report in ChromaDB (or synchronously if preferred)
        # For simplicity here, calling it synchronously. Consider background task for production.
        try:
            # Pass the original alert_data for potential metadata extraction
            process_and_store_report_in_chroma(new_report_id, report_json, alert_data)
        except Exception as e:
            # Log error but don't let it fail the main response to the user
            print(f"Error during background storage of report {new_report_id} to ChromaDB: {e}")

        return jsonify(report_json), 200

    except Exception as e:
        print(f"Error in /api/generate-soc-report endpoint: {e}") # General catch-all
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred: {str(e)}"}), 500

@app.route('/api/download-report-pdf', methods=['POST'])
def download_soc_report_pdf():
    global config # Make sure config from module level is accessible if needed, or pass it
    try:
        report_data = request.get_json()
        if not report_data:
            return jsonify({"message": "No report data provided"}), 400

        # --- CORRECTED TITLE GENERATION --- 
        current_date = datetime.datetime.now().strftime("%B %d, %Y")
        report_title = f"SOC Incident Report - {current_date}"
        # --- END CORRECTED TITLE GENERATION ---

        # Load the HTML template
        # Assumes 'templates' directory is in the same directory as app.py (i.e., 'api/templates')
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'report_template.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_string = f.read()
        
        template = Template(template_string) # Using jinja2.Template directly
        
        # Render the template with the report data
        rendered_html = template.render(data=report_data, report_title=report_title)
        
        # PDFKit options (optional, but good for defaults)
        options = {
            'page-size': 'Letter',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'custom-header' : [
                ('Accept-Encoding', 'gzip')
            ],
            'no-outline': None,
            'enable-local-file-access': None
        }

        # Generate PDF from HTML string
        if config:
            print(f"Attempting PDF generation using configured wkhtmltopdf: {config.wkhtmltopdf}")
            pdf_file = pdfkit.from_string(rendered_html, False, options=options, configuration=config)
        else:
            print("Attempting PDF generation relying on wkhtmltopdf in system PATH.")
            pdf_file = pdfkit.from_string(rendered_html, False, options=options)

        # Create a response to send the PDF file
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{report_title.replace(": ", "-").replace(" ", "_")}.pdf"'
        
        print(f"Successfully generated PDF: {report_title}.pdf")
        return response

    except FileNotFoundError:
        print("Error: The HTML template file (report_template.html) was not found.")
        return jsonify({"message": "Server error: PDF template not found."}), 500
    except OSError as e:
        # This can happen if wkhtmltopdf is not installed or not found in PATH
        print(f"OSError during PDF generation: {e}")
        if "No such file or directory: wkhtmltopdf" in str(e) or "Command not found: wkhtmltopdf" in str(e):
             print("ERROR: wkhtmltopdf not found. Please ensure it is installed and in your system PATH.")
             return jsonify({"message": "Server error: wkhtmltopdf not found. Please install it to enable PDF generation."}), 500
        return jsonify({"message": f"Server error during PDF generation (OS Error): {str(e)}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred during PDF generation: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred: {str(e)}"}), 500

def construct_rag_prompt(user_query: str, relevant_chunks: list[str]) -> str:
    """
    Constructs a prompt for the RAG LLM to answer questions based on the provided relevant chunks.
    """
    if not relevant_chunks:
        context_str = "No specific context could be retrieved from the report for this query. Please answer generally if possible or state that the information is not available."
    else:
        context_str = "\n\n---\n\n".join(relevant_chunks) # Join chunks with a separator

    prompt = (
        "You are an AI assistant whose sole purpose is to answer questions based ONLY on the provided 'Retrieved Context from SOC Incident Report'.\n"
        "Do not use any external knowledge or make assumptions beyond what is explicitly stated in the retrieved context.\n"
        "If the answer to the question cannot be found within the provided context, you MUST state that clearly, "
        "for example by saying 'The provided report context does not contain information to answer that question.' or similar.\n"
        "Do not attempt to answer if the information is not present in the context.\n\n"
        f"User Question: \"{user_query}\"\n\n"
        "Retrieved Context from SOC Incident Report:\n"
        "```text\n"
        f"{context_str}\n"
        "```\n\n"
        "Based ONLY on the Retrieved Context from SOC Incident Report provided above, answer the user's question.\n"
        "Answer:"
    )
    return prompt

@app.route('/api/query-report-rag', methods=['POST'])
def query_report_rag_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No input data provided"}), 400

        user_query = data.get('query')
        report_context_string = data.get('reportContextString') # This is the full report JSON string

        if not user_query or not report_context_string:
            return jsonify({"message": "Missing 'query' or 'reportContextString' in request"}), 400

        current_api_key = request.headers.get('X-API-KEY') or OPENAI_API_KEY
        if not current_api_key:
            print("ERROR: OpenAI API key not configured for RAG query.")
            return jsonify({"message": "OpenAI API key not configured on the server."}), 500

        report_id = str(hash(report_context_string))

        if not (_cached_report_data.get("report_id") == report_id and _cached_report_data.get("embeddings") is not None):
            print(f"Cache miss or new report. Generating embeddings for report ID: {report_id}")
            if not generate_and_cache_report_embeddings(report_id, report_context_string, current_api_key):
                print("Warning: Failed to generate report embeddings.")
                relevant_chunks_for_prompt = _cached_report_data.get("chunks", [report_context_string])
            else:
                relevant_chunks_for_prompt = get_relevant_chunks(user_query, current_api_key, top_n=5)
                if not relevant_chunks_for_prompt:
                    print("No specific relevant chunks found by similarity, using all cached chunks as context.")
                    relevant_chunks_for_prompt = _cached_report_data.get("chunks", [report_context_string])
        else: # Cache hit
            print(f"Cache hit for report ID: {report_id}. Retrieving relevant chunks.")
            relevant_chunks_for_prompt = get_relevant_chunks(user_query, current_api_key, top_n=5)
            if not relevant_chunks_for_prompt:
                print("No specific relevant chunks found by similarity (cache hit), using all cached chunks.")
                relevant_chunks_for_prompt = _cached_report_data.get("chunks", [report_context_string])
        
        rag_prompt = construct_rag_prompt(user_query, relevant_chunks_for_prompt)
        
        print(f"Attempting RAG query with refined context. Prompt length: {len(rag_prompt)} chars.")

        try:
            chat_model = ChatOpenAI(
                api_key=current_api_key,
                model=RAG_QUERY_MODEL_NAME,
                temperature=0.0,
            )
            response = chat_model.invoke(rag_prompt)
            llm_answer = response.content.strip()
            print(f"Successfully received RAG answer from LLM: {llm_answer[:100]}...")
        except Exception as e:
            print(f"Error calling LLM for RAG query: {e}")
            return jsonify({"message": f"Error communicating with LLM for RAG query: {str(e)}"}), 500
        
        return jsonify({"answer": llm_answer}), 200

    except Exception as e:
        print(f"Error in /api/query-report-rag endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred in RAG endpoint: {str(e)}"}), 500

# --- New Multi-Report RAG Chat Functions ---

def construct_multireport_rag_prompt(user_query: str, retrieved_chunks_with_metadata: list[dict]) -> str:
    """
    Constructs a prompt for the LLM to answer questions based on chunks retrieved from multiple reports.
    Each item in retrieved_chunks_with_metadata is expected to be a dict with 'document' and 'metadata' keys.
    """
    if not retrieved_chunks_with_metadata:
        context_str = "No relevant information could be found in the stored SOC reports for this query."
    else:
        contexts = []
        for item in retrieved_chunks_with_metadata:
            doc = item.get('document', '[Content not available]')
            meta = item.get('metadata', {})
            report_id_short = meta.get('report_id', 'unknown_report')[:8] # Short ID for brevity
            timestamp = meta.get('timestamp_unix', 'unknown_time')
            summary_preview = meta.get('event_summary_preview', 'N/A')
            contexts.append(f"Context from SOC Report (ID: {report_id_short}, Time: {timestamp}, Summary: {summary_preview}...):\n{doc}")
        context_str = "\n\n---\n\n".join(contexts)

    prompt = (
        "You are an AI assistant. Answer the user's question based ONLY on the following 'Retrieved Contexts from SOC Incident Reports'.\n"
        "Synthesize information if multiple contexts are provided. "
        "If the answer cannot be found, state that clearly. Do not make assumptions or use external knowledge.\n"
        "If quoting from a specific report, you can mention its ID or timestamp if relevant to the query.\n\n"
        f"User Question: \"{user_query}\"\n\n"
        "Retrieved Contexts from SOC Incident Reports:\n"
        "============================================\n"
        f"{context_str}\n"
        "============================================\n\n"
        "Based ONLY on the retrieved contexts, answer the user's question.\n"
        "Answer:"
    )
    return prompt

@app.route('/api/chat-with-soc-reports', methods=['POST'])
def chat_with_soc_reports_endpoint():
    global soc_reports_collection, OPENAI_API_KEY, RAG_QUERY_MODEL_NAME

    if soc_reports_collection is None:
        return jsonify({"message": "SOC report database is not initialized."}), 503 # Service Unavailable

    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({"message": "Missing 'query' in request"}), 400
        
        user_query = data['query']
        
        # Extract filter parameters from the request, defaulting to None if not provided
        report_id_filter = data.get('report_id_filter')
        start_date_filter = data.get('start_date_filter') # Expected format: YYYY-MM-DDTHH:MM:SSZ (ISO 8601)
        end_date_filter = data.get('end_date_filter')     # Expected format: YYYY-MM-DDTHH:MM:SSZ (ISO 8601)
        ttps_filter_str = data.get('ttps_filter')         # Comma-separated string of TTPs
        cves_filter_str = data.get('cves_filter')         # Comma-separated string of CVEs

        current_api_key = request.headers.get('X-API-KEY') or OPENAI_API_KEY
        if not current_api_key:
            print("ERROR: OpenAI API key not configured for RAG query.")
            return jsonify({"message": "OpenAI API key not configured on the server."}), 500

        embedding_model = get_report_embedding_model(current_api_key)
        query_embedding = embedding_model.embed_query(user_query)

        # --- Construct where_conditions for ChromaDB query ---
        where_conditions = {}
        active_filters = []

        if report_id_filter:
            active_filters.append({"report_id": {"$eq": report_id_filter}})
        
        # Timestamp filtering
        timestamp_conditions = {}
        if start_date_filter:
            try:
                # Remove Z if present, as fromisoformat doesn't always like it, then convert to UTC timestamp
                start_dt = datetime.datetime.fromisoformat(start_date_filter.replace('Z', ''))
                # If the datetime object is naive, assume it's UTC then get timestamp
                # If it's timezone-aware, convert to UTC then get timestamp
                if start_dt.tzinfo is None or start_dt.tzinfo.utcoffset(start_dt) is None:
                    start_dt = start_dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    start_dt = start_dt.astimezone(datetime.timezone.utc)
                active_filters.append({"timestamp_unix": {"$gte": int(start_dt.timestamp())}})
            except ValueError as ve:
                return jsonify({"message": f"Invalid start_date format: {start_date_filter}. Error: {ve}"}), 400
        
        if end_date_filter:
            try:
                end_dt = datetime.datetime.fromisoformat(end_date_filter.replace('Z', ''))
                if end_dt.tzinfo is None or end_dt.tzinfo.utcoffset(end_dt) is None:
                    end_dt = end_dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    end_dt = end_dt.astimezone(datetime.timezone.utc)
                active_filters.append({"timestamp_unix": {"$lte": int(end_dt.timestamp())}})
            except ValueError as ve:
                return jsonify({"message": f"Invalid end_date format: {end_date_filter}. Error: {ve}"}), 400
        
        if len(active_filters) == 1:
            where_conditions = active_filters[0]
        elif len(active_filters) > 1:
            where_conditions = {"$and": active_filters}
        # --- End of constructing where_conditions ---

        n_results = 5 # Number of chunks to retrieve
        
        query_params = {
            "query_embeddings": [query_embedding],
            "n_results": n_results,
            "include": ["documents", "metadatas"]
        }
        if where_conditions:
            query_params["where"] = where_conditions
            print(f"Querying SOC reports collection for: '{user_query[:100]}...' with filters: {where_conditions} and {n_results} results.")
        else:
            print(f"Querying SOC reports collection for: '{user_query[:100]}...' with {n_results} results (no filters).")
            
        results = soc_reports_collection.query(**query_params)

        retrieved_items = []
        if results and results.get('ids') and results.get('ids')[0]: # Check if there are any results for the first query
            ids_list = results['ids'][0]
            docs_list = results['documents'][0] if results.get('documents') else [None] * len(ids_list)
            metadatas_list = results['metadatas'][0] if results.get('metadatas') else [{}] * len(ids_list)

            for i, doc_id in enumerate(ids_list):
                retrieved_items.append({
                    "id": doc_id,
                    "document": docs_list[i] if docs_list and i < len(docs_list) else None,
                    "metadata": metadatas_list[i] if metadatas_list and i < len(metadatas_list) else {}
                })
            print(f"Retrieved {len(retrieved_items)} chunks from ChromaDB.")
        else:
            print("No relevant chunks found in ChromaDB for the query.")
        
        # Construct prompt for LLM
        final_rag_prompt = construct_multireport_rag_prompt(user_query, retrieved_items)
        print(f"Multi-report RAG prompt length: {len(final_rag_prompt)} chars.")

        # Call LLM
        chat_model = ChatOpenAI(
            api_key=current_api_key,
            model=RAG_QUERY_MODEL_NAME, 
            temperature=0.0
        )
        response = chat_model.invoke(final_rag_prompt)
        llm_answer = response.content.strip()

        print(f"LLM answer for multi-report query: {llm_answer[:100]}...")
        # print(f"DEBUG: Retrieved items for source_chunks: {retrieved_items}") 
        
        # Prepare unique source report IDs for the frontend
        unique_source_report_ids = []
        if retrieved_items:
            seen_report_ids = set()
            for item in retrieved_items:
                metadata = item.get("metadata", {})
                report_id = metadata.get("report_id")
                if report_id and report_id not in seen_report_ids:
                    seen_report_ids.add(report_id)
                    unique_source_report_ids.append(report_id)
        
        # print(f"DEBUG: About to jsonify: answer_type={type(llm_answer)}, source_chunks_type={type(unique_source_report_ids)}, source_chunks_content={unique_source_report_ids}")
        return jsonify({"answer": llm_answer, "source_report_ids": unique_source_report_ids}), 200

    except Exception as e:
        print(f"Error in /api/chat-with-soc-reports endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred: {str(e)}"}), 500

# --- End New Multi-Report RAG Chat Functions ---

@app.route('/api/get-report/<report_id>', methods=['GET'])
def get_report_by_id(report_id: str):
    """
    Get a specific SOC report by its ID from ChromaDB.
    Returns the full report content and metadata.
    """
    global soc_reports_collection

    if soc_reports_collection is None:
        return jsonify({"message": "SOC report database is not initialized."}), 503

    try:
        # Query ChromaDB for all chunks with this report_id
        results = soc_reports_collection.get(
            where={"report_id": {"$eq": report_id}},
            include=["documents", "metadatas"]
        )

        if not results or not results.get('ids') or len(results['ids']) == 0:
            return jsonify({"message": f"Report with ID {report_id} not found."}), 404

        # Reconstruct the full report from chunks
        chunks_data = []
        report_metadata = None
        
        ids_list = results['ids']
        docs_list = results.get('documents', [])
        metadatas_list = results.get('metadatas', [])

        for i, chunk_id in enumerate(ids_list):
            chunk_doc = docs_list[i] if i < len(docs_list) else ""
            chunk_metadata = metadatas_list[i] if i < len(metadatas_list) else {}
            
            chunks_data.append({
                "chunk_id": chunk_id,
                "content": chunk_doc,
                "source_section": chunk_metadata.get("source_section", "unknown"),
                "metadata": chunk_metadata
            })
            
            # Use the first chunk's metadata as the report metadata
            if report_metadata is None:
                report_metadata = chunk_metadata

        # Try to reconstruct the original report structure
        report_content = {
            "report_id": report_id,
            "chunks": chunks_data,
            "metadata": report_metadata,
            "event_summary": report_metadata.get("event_summary_preview", "") if report_metadata else "",
            "timestamp": report_metadata.get("timestamp_unix", 0) if report_metadata else 0,
            "mitre_ttps": [],
            "cves": []
        }

        # Handle mitre_ttps - convert from comma-separated string to array
        if report_metadata and report_metadata.get("mitre_ttps"):
            ttps_str = report_metadata.get("mitre_ttps", "")
            if isinstance(ttps_str, str) and ttps_str.strip():
                report_content["mitre_ttps"] = [ttp.strip() for ttp in ttps_str.split(',') if ttp.strip()]
            elif isinstance(ttps_str, list):
                report_content["mitre_ttps"] = ttps_str

        # Handle cves - convert from comma-separated string to array  
        if report_metadata and report_metadata.get("cves"):
            cves_str = report_metadata.get("cves", "")
            if isinstance(cves_str, str) and cves_str.strip():
                report_content["cves"] = [cve.strip() for cve in cves_str.split(',') if cve.strip()]
            elif isinstance(cves_str, list):
                report_content["cves"] = cves_str

        return jsonify(report_content), 200

    except Exception as e:
        print(f"Error in /api/get-report/{report_id} endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred: {str(e)}"}), 500

def construct_title_generation_prompt(user_query: str) -> str:
    """
    Constructs a prompt for the LLM to generate a concise chat title.
    """
    # Ensure user_query is properly escaped if it contains quotes, though for this prompt structure, it might be okay.
    # The key is to clearly delineate the user's query within the prompt structure.
    prompt = (
        f"Based on the following user query, generate a very short, concise, and descriptive title "
        f"(ideally 3-7 words) that summarizes the main topic of the query. "
        f"The title should be suitable for a chat history list. Output only the title itself, with no extra text or quotes.\n\n"
        f"User Query:\n{user_query}\n\n"
        f"Title:"
    )
    return prompt

@app.route('/api/generate-chat-title', methods=['POST'])
def generate_chat_title_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No input data provided"}), 400

        user_query = data.get('user_query')

        if not user_query:
            return jsonify({"message": "Missing 'user_query' in request"}), 400

        if not OPENAI_API_KEY:
            print("ERROR: OpenAI API key not configured for title generation.")
            return jsonify({"message": "OpenAI API key not configured on the server."}), 500

        title_prompt = construct_title_generation_prompt(user_query)
        
        # For title generation, we can use a fast and cost-effective model.
        title_model_name = os.environ.get("TITLE_MODEL_NAME", RAG_QUERY_MODEL_NAME) 
        if not title_model_name:
            title_model_name = "gpt-3.5-turbo"

        print(f"Attempting title generation with model: {title_model_name}. Query: {user_query[:50]}...")

        try:
            chat_model = ChatOpenAI(
                api_key=OPENAI_API_KEY,
                model=title_model_name,
                temperature=0.1,
                streaming=True
            )
            
            def generate():
                import time
                for chunk in chat_model.stream(title_prompt):
                    if chunk.content:
                        # Split content into characters and add delay
                        for char in chunk.content:
                            yield char
                            time.sleep(0.05)  # 50ms delay between characters

            return Response(generate(), mimetype='text/event-stream')

        except Exception as e:
            print(f"Error calling LLM for title generation: {e}")
            return jsonify({"message": f"Error communicating with LLM for title generation: {str(e)}"}), 500
        
    except Exception as e:
        print(f"Error in /api/generate-chat-title endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred in title generation endpoint: {str(e)}"}), 500

# --- Trend Analysis Endpoints ---
@app.route('/api/trends/ttp-frequency', methods=['GET'])
def get_ttp_frequency_trends():
    global soc_reports_collection

    if soc_reports_collection is None:
        return jsonify({"message": "SOC report database is not initialized."}), 503

    try:
        start_date_str = request.args.get('start_date') # Expected format: YYYY-MM-DDTHH:MM:SSZ
        end_date_str = request.args.get('end_date')     # Expected format: YYYY-MM-DDTHH:MM:SSZ

        active_filters = []
        if start_date_str:
            try:
                # Remove Z if present, as fromisoformat doesn't always like it, then convert to UTC timestamp
                start_dt = datetime.datetime.fromisoformat(start_date_str.replace('Z', ''))
                # If the datetime object is naive, assume it's UTC then get timestamp
                # If it's timezone-aware, convert to UTC then get timestamp
                if start_dt.tzinfo is None or start_dt.tzinfo.utcoffset(start_dt) is None:
                    start_dt = start_dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    start_dt = start_dt.astimezone(datetime.timezone.utc)
                active_filters.append({"timestamp_unix": {"$gte": int(start_dt.timestamp())}})
            except ValueError as ve:
                return jsonify({"message": f"Invalid start_date format: {start_date_str}. Error: {ve}"}), 400
        
        if end_date_str:
            try:
                end_dt = datetime.datetime.fromisoformat(end_date_str.replace('Z', ''))
                if end_dt.tzinfo is None or end_dt.tzinfo.utcoffset(end_dt) is None:
                    end_dt = end_dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    end_dt = end_dt.astimezone(datetime.timezone.utc)
                active_filters.append({"timestamp_unix": {"$lte": int(end_dt.timestamp())}})
            except ValueError as ve:
                return jsonify({"message": f"Invalid end_date format: {end_date_str}. Error: {ve}"}), 400
        
        where_conditions = None
        if len(active_filters) == 1:
            where_conditions = active_filters[0]
        elif len(active_filters) > 1:
            where_conditions = {"$and": active_filters}
        
        print(f"Fetching TTP frequency data with filters: {where_conditions if where_conditions else 'None'}")

        # Fetch all records matching the (optional) date filters.
        # We use soc_reports_collection.get() to retrieve by filter without vector search.
        # We need to retrieve the 'metadatas' to access 'mitre_ttps'.
        # The get() method can be slow if there are millions of entries. 
        # For very large datasets, consider alternative aggregation strategies or paginated processing.
        if where_conditions:
            results = soc_reports_collection.get(where=where_conditions, include=["metadatas"]) 
        else:
            results = soc_reports_collection.get(include=["metadatas"]) # Get all if no date filter
        
        all_ttps = []
        if results and results.get('metadatas'):
            for metadata_item in results['metadatas']:
                if metadata_item and isinstance(metadata_item.get('mitre_ttps'), str):
                    ttps_str = metadata_item['mitre_ttps']
                    if ttps_str: # Ensure not an empty string
                        ttps_list = [ttp.strip() for ttp in ttps_str.split(',') if ttp.strip()]
                        all_ttps.extend(ttps_list)
        
        if not all_ttps:
            return jsonify({"message": "No TTP data found for the given criteria.", "ttp_frequency": {}}), 200

        ttp_counts = Counter(all_ttps)
        # Sort by frequency descending
        sorted_ttp_counts = dict(sorted(ttp_counts.items(), key=lambda item: item[1], reverse=True))

        print(f"Successfully calculated TTP frequencies. Found {len(sorted_ttp_counts)} unique TTPs.")
        return jsonify({"ttp_frequency": sorted_ttp_counts}), 200

    except Exception as e:
        print(f"Error in /api/trends/ttp-frequency endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"An unexpected server error occurred: {str(e)}"}), 500

# Extract YAML code block only
def extract_yaml_block(text: str) -> str:
    match = re.search(r"```yaml(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    else:
        # fallback: maybe it's already raw YAML
        return text.strip()

def post_process_soc_report(report_json: dict) -> dict:
    """
    Post-processes the SOC report JSON to clean up formatting issues,
    particularly handling escaped newlines and ensuring proper text formatting.
    """
    def clean_text(text: str) -> str:
        if not isinstance(text, str):
            return text
        
        # Handle various escaped newline patterns
        # First, handle quadruple backslash newlines (\\\\n)
        text = text.replace('\\\\n\\\\n', '\n\n')
        text = text.replace('\\\\n', '\n')
        
        # Handle double backslash newlines (\\n)
        text = text.replace('\\n\\n', '\n\n')  
        text = text.replace('\\n', '\n')
        
        # Clean up excessive newlines (more than 2 consecutive)
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Remove leading/trailing whitespace
        text = text.strip()
        
        return text
    
    try:
        # Clean Event Summary
        if 'eventSummary' in report_json:
            report_json['eventSummary'] = clean_text(report_json['eventSummary'])
        
        # Clean Technical Analysis
        if 'technicalAnalysis' in report_json:
            report_json['technicalAnalysis'] = clean_text(report_json['technicalAnalysis'])
        
        # Clean System Remediation
        if 'systemRemediation' in report_json:
            report_json['systemRemediation'] = clean_text(report_json['systemRemediation'])
        
        # Clean Defensive Rules description
        if 'defensiveRules' in report_json and isinstance(report_json['defensiveRules'], dict):
            if 'description' in report_json['defensiveRules']:
                report_json['defensiveRules']['description'] = clean_text(report_json['defensiveRules']['description'])
            
            # Clean individual rule descriptions
            if 'rules' in report_json['defensiveRules'] and isinstance(report_json['defensiveRules']['rules'], list):
                for rule in report_json['defensiveRules']['rules']:
                    if isinstance(rule, dict) and 'description' in rule:
                        rule['description'] = clean_text(rule['description'])
        
        # Clean MITRE ATT&CK table descriptions
        if 'mitreAttackTable' in report_json and isinstance(report_json['mitreAttackTable'], list):
            for technique in report_json['mitreAttackTable']:
                if isinstance(technique, dict) and 'description' in technique:
                    technique['description'] = clean_text(technique['description'])
        
        print("Successfully post-processed SOC report formatting.")
        return report_json
        
    except Exception as e:
        print(f"Error during SOC report post-processing: {e}")
        return report_json  # Return original if processing fails

if __name__ == "__main__":
    # Initialize components when app starts
    initialize_sigma()
    app.run(debug=True, host='0.0.0.0', port=5000) 
    