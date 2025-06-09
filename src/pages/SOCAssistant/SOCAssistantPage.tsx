import React, { useState, useRef, useEffect } from 'react';
import FileUpload from './components/FileUpload';
import type { SocReportResponse, SocReportRule } from '../../hooks/useApi'; // Import useApi and response types
import useApi from '../../hooks/useApi'; // Regular import for useApi hook itself
import { AlertTriangleIcon, CheckCircle2Icon, Loader2Icon, FileTextIcon, ShieldAlertIcon, TerminalIcon, WrenchIcon, DownloadIcon } from 'lucide-react';

// Define a type for the parsed JSON alert data (can be expanded later)
// Ensure this matches or is compatible with what your ELK alerts provide
interface ElkAlert {
  _index: string;
  _id: string;
  _score: number | null;
  _source: { 
    // Common fields, adjust to your specific alert structure
    timestamp?: string;
    rule?: { name?: string; level?: number; description?: string; id?: string; };
    agent?: { id?: string; name?: string; ip?: string; };
    source?: { ip?: string; port?: number; user?: { name?: string } };
    destination?: { ip?: string; port?: number; };
    event?: { action?: string; category?: string | string[]; type?: string | string[]; module?: string; dataset?: string; original?: string; };
    message?: string;
    // Add any other relevant fields from your typical ELK alerts
    [key: string]: any; 
  };
}

// Define the system architecture string (this could also potentially come from a configuration or context)
const SYSTEM_ARCHITECTURE = "System Architecture Context: The system includes the following main components: The Internet is connected to a WAF (Web Application Firewall), where the WAF protects the Web Server from attacks such as SQL Injection, XSS, RCE, etc., by filtering and blocking malicious traffic. Valid traffic is then routed through a Router integrated with IDS (Snort), which helps monitor and detect abnormal behavior in the internal network. Snort sends logs to the ELK SIEM system for analysis. The ELK SIEM is integrated with MISP, a component specializing in collecting IoCs (Indicators of Compromise) from threat intelligence sources and converting them into Sigma rules to detect threats in log data. Clients (computers) and the web server within the system are sources of event generation.";

// Define the props for the SOC Assistant page
interface SOCAssistantPageProps {
  initialState?: {
    alertFile: File | null;
    alertData: ElkAlert[] | null;
    socReportContent: SocReportResponse | null;
  };
  onStateChange?: (newState: Partial<{
    alertFile: File | null;
    alertData: ElkAlert[] | null;
    socReportContent: SocReportResponse | null;
  }>) => void;
}

// Dummy data for PDF testing - In a production app, you'd likely remove this
const DUMMY_SOC_REPORT_FOR_PDF_TESTING: SocReportResponse = {
  eventSummary: "This is a DUMMY event summary for PDF testing. It mentions some keywords like alert, investigation, and findings to simulate real text flow.",
  
  technicalAnalysis: "DUMMY Technical Analysis Section: This section would describe attack details like IPs (DUMMY_IP), URLs (DUMMY_URL), and techniques (T1566 - Phishing). The attacker used Web Protocols (T1071.001) for C2 communication and executed malicious code via Command and Scripting Interpreter (T1059). The attack began when a user opened a malicious email attachment, executing a PowerShell script (T1059.001) that established persistence via a scheduled task (T1053.005).\n\nIn another attack phase, the threat actor attempted lateral movement (T1021) using stolen credentials.",
  
  defensiveRules: {
    description: "DUMMY Defensive Rules to detect and/or prevent similar attacks:",
    rules: [
      { type: "snort", content: "alert tcp any any -> $HOME_NET any (msg:\"DUMMY Snort IDS Rule - Potential C2 Communication\"; flow:established; content:\"|00 01 86 a5|\"; depth:4; sid:1000001; rev:1;)", description: "This rule detects suspicious network traffic matching command and control patterns." },
      { type: "modsecurity", content: "SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* \"DUMMY_PATTERN\" \"id:1000001,phase:2,deny,log,status:403,msg:'Potential SQL Injection Attack'\"", description: "This ModSecurity rule blocks potential SQL injection attempts targeting web applications." }
    ]
  },
  
  systemRemediation: "DUMMY System Remediation Recommendations:\n1. Isolate affected endpoints immediately based on DUMMY_IOCs.\n2. Reset compromised user credentials for all DUMMY_USERS.\n3. Scan the environment for known persistence mechanisms (T1547).\n4. Block C2 domains/IPs: DUMMY_C2_DOMAIN, DUMMY_C2_IP.\n5. Review and update firewall and WAF rules to prevent recurrence. This involves checking DUMMY_POLICY_X.\n6. Conduct a thorough security awareness training for users regarding phishing attempts (T1566). More dummy text to ensure this section also has enough content to potentially span lines or paragraphs, helping to verify the overall PDF layout and formatting including line spacing and font rendering.",
  
  mitreAttackTable: [
    { stage: "Initial Access", techniqueName: "Phishing", techniqueCode: "T1566", description: "User opened malicious email attachment containing PowerShell script" },
    { stage: "Execution", techniqueName: "PowerShell", techniqueCode: "T1059.001", description: "Malicious PowerShell script executed to establish foothold" },
    { stage: "Persistence", techniqueName: "Scheduled Task/Job", techniqueCode: "T1053.005", description: "Created scheduled task for persistence mechanism" },
    { stage: "Command and Control", techniqueName: "Web Protocols", techniqueCode: "T1071.001", description: "Used HTTP/HTTPS for C2 communication with external server" }
  ]
};

const SOCAssistantPage: React.FC<SOCAssistantPageProps> = ({ initialState, onStateChange }) => {
  const [alertFile, setAlertFile] = useState<File | null>(initialState?.alertFile || null);
  const [alertData, setAlertData] = useState<ElkAlert[] | null>(initialState?.alertData || null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [showApiKeyWarning, setShowApiKeyWarning] = useState<boolean>(false);

  const { 
    loading: apiLoading,
    error: apiError,
    generateSocReport,
  } = useApi();
  
  const [socReportContent, setSocReportContent] = useState<SocReportResponse | null>(initialState?.socReportContent || null);
  const [reportGenerationError, setReportGenerationError] = useState<string | null>(null);
  const reportContentRef = useRef<HTMLDivElement>(null); // Ref for the report content div

  const [isDownloadingPdf, setIsDownloadingPdf] = useState<boolean>(false); // New state for PDF download loading
  const [pdfDownloadError, setPdfDownloadError] = useState<string | null>(null); // New state for PDF download errors

  // Update parent component state when local state changes
  useEffect(() => {
    if (onStateChange) {
      onStateChange({
        alertFile,
        alertData,
        socReportContent
      });
    }
  }, [alertFile, alertData, socReportContent, onStateChange]);

  useEffect(() => {
    // Check for API key on component mount
    const apiKey = localStorage.getItem('openai_api_key');
    if (!apiKey) {
      setShowApiKeyWarning(true);
    }
  }, []);

  const handleFileSelect = async (file: File) => {
    setAlertFile(file);
    setParseError(null);
    setAlertData(null);
    setSocReportContent(null);
    setReportGenerationError(null);

    try {
      const fileContent = await file.text();
      const jsonData = JSON.parse(fileContent);
      
      if (Array.isArray(jsonData) && jsonData.length > 0) {
        setAlertData(jsonData as ElkAlert[]);
      } else if (typeof jsonData === 'object' && jsonData !== null && Object.keys(jsonData).length > 0) {
        setAlertData([jsonData as ElkAlert]); // Wrap single alert in an array
      } else {
        setParseError('Invalid or empty JSON structure. Expected a non-empty array of alerts or a single alert object.');
        setAlertFile(null);
        setAlertData(null);
      }
    } catch (error) {
      console.error("Error parsing JSON file:", error);
      setParseError('Failed to parse JSON file. Please ensure it is valid JSON and not empty.');
      setAlertFile(null);
      setAlertData(null);
    }
  };

  const handleGenerateReport = async () => {
    if (!alertData) { // Check if actual alertData is present
      setReportGenerationError('No alert data available to generate a report.');
      return;
    }
    setReportGenerationError(null);
    setSocReportContent(null);

    // --- FOR PDF TESTING WITH DUMMY DATA --- 
    // The following lines are commented out to ensure live API call
    // setSocReportContent(DUMMY_SOC_REPORT_FOR_PDF_TESTING); 
    // if (DUMMY_SOC_REPORT_FOR_PDF_TESTING) return; 
    // --- END OF PDF TESTING SECTION ---

    // This check is technically redundant now if the above dummy logic is fully out,
    // but kept for safety, ensuring alertData is present for an actual call.
    if (!alertData) {
        setReportGenerationError('Alert data is missing for actual report generation.');
        return;
    }
    const report = await generateSocReport(alertData, SYSTEM_ARCHITECTURE);
    if (report) {
      setSocReportContent(report);
    } else {
      setReportGenerationError(apiError?.message || 'Failed to generate SOC report. Check console for details.');
    }
  };

  const handleDownloadPdf = async () => {
    if (!socReportContent || isDownloadingPdf) {
      console.log("PDF download cannot start: No report content or download already in progress.");
      setPdfDownloadError("Cannot download PDF: Report content is not available or a download is already in progress.");
      return;
    }
    console.log("Starting PDF download process via server...");
    setIsDownloadingPdf(true);
    setPdfDownloadError(null);

    try {
      const response = await fetch('/api/download-report-pdf', { // Assuming backend runs on the same origin or proxied
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(socReportContent), // Send the whole report content
      });

      if (!response.ok) {
        // Try to get error message from server response body
        let errorMsg = `Server error: ${response.status} ${response.statusText}`;
        try {
            const errorData = await response.json();
            errorMsg = errorData.message || errorMsg;
        } catch (e) {
            // Could not parse JSON, use default error message
        }
        throw new Error(errorMsg);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      // Extract filename from Content-Disposition header if possible, otherwise generate one
      let filename = "soc_incident_report.pdf";
      const disposition = response.headers.get('Content-Disposition');
      if (disposition && disposition.indexOf('attachment') !== -1) {
        // Regex to find filename. Handles quoted and unquoted filenames.
        // Example: filename="report.pdf" or filename=report.pdf
        const filenameRegex = /filename(?:\*=[^\'"]*''([^\'"]+)|="([^"]*)"|=([^;]*))/i;
        const matches = filenameRegex.exec(disposition);
        if (matches != null) {
          // Order of preference for matches: UTF-8 (group 1), quoted (group 2), unquoted (group 3)
          filename = matches[1] || matches[2] || matches[3] || filename;
          // Decode URI component if it was a UTF-8 filename part
          if (matches[1]) {
            try {
                filename = decodeURIComponent(filename);
            } catch (e) {
                console.warn("Could not decode URI component in filename", filename, e);
            }
          }
        }
      }
      a.download = filename;
      
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
      console.log("PDF downloaded successfully from server.");

    } catch (error) {
      console.error("Error downloading PDF from server:", error);
      setPdfDownloadError(error instanceof Error ? error.message : 'Failed to download PDF from server. Check console.');
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const renderRuleContent = (rule: SocReportRule) => {
    // Simple rendering, can be enhanced with syntax highlighting later
    return (
      <div key={rule.type + rule.content.slice(0,20)} className='mb-3 p-3 bg-slate-50 rounded border border-gray-200'>
        <p className='text-xs font-semibold text-indigo-600 mb-1 capitalize'>{rule.type} Rule:</p>
        {rule.description && <p className='text-xs text-gray-500 mb-1'>{rule.description}</p>}
        <pre className='bg-gray-800 text-white p-2 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all'>{rule.content}</pre>
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col items-center bg-gray-100 p-4 md:p-6 overflow-y-auto">
      <div className="w-full max-w-5xl space-y-6 md:space-y-8">
        <header className="text-center">
          <h1 className="text-2xl md:text-3xl font-bold text-gray-800">SOC Incident Analysis & Reporting</h1>
          <p className="mt-1 md:mt-2 text-sm md:text-base text-gray-600">
            Upload ELK SIEM alert JSON to generate a detailed incident report by SageHunt.
          </p>
        </header>

        {/* API Key Warning Message */}
        {showApiKeyWarning && (
          <div className="mb-4 p-4 bg-yellow-50 border border-yellow-300 rounded-lg text-sm text-yellow-700 shadow-sm" role="alert">
            <div className="flex items-start">
              <AlertTriangleIcon className="w-5 h-5 mr-3 flex-shrink-0 text-yellow-500 mt-0.5" />
              <div>
                <p className="font-semibold text-yellow-800">API Key Missing</p>
                <p className="mt-1">
                  The OpenAI API key is not configured. Report generation and other AI features will not work.
                </p>
                {/* <p className="text-xs mt-2">
                  Please go to the{' '}
                  <Link to="/settings" className="font-medium text-yellow-800 hover:text-yellow-900 underline">
                    Settings page <SettingsIcon size={12} className="inline-block ml-0.5 mb-0.5"/>
                  </Link>
                  {' '}to add your API key.
                </p> */}
              </div>
            </div>
          </div>
        )}

        <section className="bg-white p-4 md:p-6 shadow-md rounded-lg">
          <h2 className="text-lg md:text-xl font-semibold text-gray-700 mb-3 md:mb-4 border-b pb-2">1. Upload Alert File</h2>
          <FileUpload onFileSelect={handleFileSelect} />
          {parseError && (
            <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md text-center flex items-center justify-center">
              <AlertTriangleIcon className="w-5 h-5 text-red-500 mr-2" />
              <p className="text-sm text-red-600">Parse Error: {parseError}</p>
            </div>
          )}
          {alertFile && !parseError && (
            <div className="mt-3 p-3 bg-green-50 border border-green-200 rounded-md text-center flex items-center justify-center">
              <CheckCircle2Icon className="w-5 h-5 text-green-600 mr-2" />
              <p className="text-sm text-green-700">
                Successfully loaded: <strong>{alertFile.name}</strong>.
                {alertData && ` Found ${alertData.length} alert(s). Ready to generate report.`}
              </p>
            </div>
          )}
        </section>

        {/* Report Generation Error Display - Enhanced */}
        {reportGenerationError && (
          <div className="my-4 p-4 bg-red-50 border border-red-300 rounded-lg text-sm text-red-700 shadow-sm" role="alert">
            <div className="flex items-start">
              <ShieldAlertIcon className="w-5 h-5 mr-3 flex-shrink-0 text-red-500 mt-0.5" />
              <div>
                <p className="font-semibold text-red-800">Report Generation Failed</p>
                <p className="mt-1">{reportGenerationError}</p>
                <p className="text-xs mt-2 text-red-600">
                  Please ensure the uploaded alert data is valid and your API key is correctly configured in settings. 
                  Check the browser console for more technical details if the issue persists.
                </p>
              </div>
            </div>
          </div>
        )}

        {alertData && !parseError && (
          <section className="bg-white p-4 md:p-6 shadow-md rounded-lg">
            <h2 className="text-lg md:text-xl font-semibold text-gray-700 mb-3 md:mb-4 border-b pb-2">2. Generate Report</h2>
            <div className="flex justify-center">
              <button 
                onClick={handleGenerateReport}
                disabled={!alertData || apiLoading} 
                className={`px-6 py-2.5 font-medium text-sm rounded-md shadow-sm flex items-center justify-center transition-colors 
                            ${(!alertData || apiLoading) 
                              ? 'bg-gray-400 text-gray-700 cursor-not-allowed' 
                              : 'bg-blue-600 text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 active:bg-blue-800 cursor-pointer'}
                          `}
              >
                {apiLoading ? (
                  <Loader2Icon className="animate-spin w-5 h-5 mr-2" />
                ) : (
                  <>
                    <FileTextIcon className="w-5 h-5 mr-2" />
                    Generate Incident Report
                  </>
                )}
              </button>
            </div>
            {reportGenerationError && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md text-center flex items-center justify-center">
                <AlertTriangleIcon className="w-5 h-5 text-red-500 mr-2" />
                <p className="text-sm text-red-600">Report Error: {reportGenerationError}</p>
              </div>
            )}
          </section>
        )}

        {(apiLoading && !socReportContent && !DUMMY_SOC_REPORT_FOR_PDF_TESTING) && (
            <div className="text-center p-6">
                <Loader2Icon className="animate-spin w-10 h-10 text-blue-600 mx-auto mb-3" />
                <p className='text-gray-600'>The AI is analyzing the alert and crafting your report. Please wait...</p>
            </div>
        )}

        {socReportContent && (
          <section ref={reportContentRef} className="bg-white p-4 md:p-6 shadow-md rounded-lg animate-fade-in">
            <div className="flex justify-between items-center mb-4 md:mb-6 border-b pb-3">
                <h2 className="text-xl md:text-2xl font-semibold text-gray-800 text-center flex-grow">Incident Report: {alertFile?.name || (socReportContent === DUMMY_SOC_REPORT_FOR_PDF_TESTING ? 'Dummy Report' : 'Details')}</h2>
                <button
                    onClick={handleDownloadPdf}
                    disabled={isDownloadingPdf || apiLoading}
                    className="ml-4 px-4 py-2 bg-green-600 text-white font-medium text-sm rounded-md shadow-sm hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 disabled:bg-gray-400 flex items-center transition-colors cursor-pointer"
                >
                    {isDownloadingPdf ? (
                        <>
                            <Loader2Icon className="animate-spin w-5 h-5 mr-2" />
                            Downloading...
                        </>
                    ) : (
                        <>
                            <DownloadIcon size={18} className="mr-2"/>
                            Download PDF
                        </>
                    )}
                </button>
            </div>
            {/* Enhanced PDF Download Error Display */}
            {pdfDownloadError && (
              <div className="my-3 p-3 bg-red-100 border border-red-300 rounded-lg text-sm text-red-700 shadow-sm" role="alert">
                <div className="flex items-center">
                  <AlertTriangleIcon className="w-5 h-5 mr-2.5 flex-shrink-0 text-red-500" />
                  <div>
                    <p className="font-semibold text-red-800">PDF Download Failed</p>
                    <p>{pdfDownloadError}</p>
                  </div>
                </div>
              </div>
            )}
            
            <div ref={reportContentRef} id="actual-report-content-for-pdf">
              <div className="mb-4 md:mb-6 p-3 md:p-4 border border-gray-200 rounded-md bg-slate-50 report-section">
                <h3 className="text-md md:text-lg font-semibold text-slate-700 mb-2 flex items-center"><FileTextIcon className='w-5 h-5 mr-2 text-slate-500'/>I. Event Summary</h3>
                <p className="text-sm md:text-base text-gray-700 whitespace-pre-wrap">{socReportContent.eventSummary}</p>
              </div>

              <div className="mb-4 md:mb-6 p-3 md:p-4 border border-gray-200 rounded-md bg-slate-50 report-section">
                <h3 className="text-md md:text-lg font-semibold text-slate-700 mb-2 flex items-center"><TerminalIcon className='w-5 h-5 mr-2 text-slate-500'/>II. Technical Analysis</h3>
                <p className="text-sm md:text-base text-gray-700 whitespace-pre-wrap">{socReportContent.technicalAnalysis}</p>
              </div>

              <div className="mb-4 md:mb-6 p-3 md:p-4 border border-gray-200 rounded-md bg-slate-50 report-section">
                <h3 className="text-md md:text-lg font-semibold text-slate-700 mb-2 flex items-center"><ShieldAlertIcon className='w-5 h-5 mr-2 text-slate-500'/>III. Defensive Rules</h3>
                <p className="text-sm md:text-base text-gray-700 mb-3 whitespace-pre-wrap">{socReportContent.defensiveRules.description}</p>
                {socReportContent.defensiveRules.rules && socReportContent.defensiveRules.rules.length > 0 ? (
                  socReportContent.defensiveRules.rules.map(renderRuleContent)
                ) : (
                  <p className='text-sm text-gray-500 italic'>No specific rules were generated for this event.</p>
                )}
              </div>

              <div className="p-3 md:p-4 border border-gray-200 rounded-md bg-slate-50 report-section">
                <h3 className="text-md md:text-lg font-semibold text-slate-700 mb-2 flex items-center"><WrenchIcon className='w-5 h-5 mr-2 text-slate-500'/>IV. System Remediation Recommendations</h3>
                <p className="text-sm md:text-base text-gray-700 whitespace-pre-wrap">{socReportContent.systemRemediation}</p>
              </div>

              {/* MITRE ATT&CK Table Section */}
              {socReportContent.mitreAttackTable && socReportContent.mitreAttackTable.length > 0 && (
                <div className="p-3 md:p-4 border border-gray-200 rounded-md bg-slate-50 report-section">
                  <h3 className="text-md md:text-lg font-semibold text-slate-700 mb-3 flex items-center">
                    <ShieldAlertIcon className='w-5 h-5 mr-2 text-slate-500'/>
                    V. MITRE ATT&CK Techniques
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="min-w-full bg-white border border-gray-300 rounded-lg">
                      <thead className="bg-gray-100">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider border-b border-gray-300">
                            Stage
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider border-b border-gray-300">
                            Technique
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider border-b border-gray-300">
                            Code
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider border-b border-gray-300">
                            Description
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {socReportContent.mitreAttackTable.map((technique, index) => (
                          <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                            <td className="px-4 py-3 text-sm text-gray-900 border-r border-gray-200">
                              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                {technique.stage}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900 border-r border-gray-200">
                              {technique.techniqueName}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-900 border-r border-gray-200">
                              <code className="bg-gray-100 px-2 py-1 rounded text-xs font-mono">
                                {technique.techniqueCode}
                              </code>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-700">
                              {technique.description}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default SOCAssistantPage; 