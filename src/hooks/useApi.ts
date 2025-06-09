import { useState } from 'react';

interface ApiResponse {
  sigmaRule: string;
  eqlQuery: string;
}

interface ApiError {
  message: string;
  status?: number;
}

// Define the structure for the SOC report response from the API
export interface SocReportRule {
  type: 'snort' | 'modsecurity' | 'sigma' | 'other'; // Type of rule
  content: string; // The rule itself
  description?: string; // Optional description of the rule
}

export interface MitreAttackTechnique {
  stage: string; // MITRE ATT&CK tactic/stage
  techniqueName: string; // Full name of the technique
  techniqueCode: string; // MITRE ATT&CK technique ID
  description: string; // Incident-specific description
}

export interface SocReportResponse {
  eventSummary: string;
  technicalAnalysis: string;
  defensiveRules: {
    description: string; // General description for this section
    rules: SocReportRule[]; // Array of different types of rules
  };
  systemRemediation: string;
  mitreAttackTable: MitreAttackTechnique[]; // Array of MITRE ATT&CK techniques
  // We can add more fields as needed, e.g., severity, attacker IOcs, etc.
}

// Define the structure for the RAG query response
export interface RagQueryResponse {
  answer: string;
}

// Define the structure for the SOC Chat RAG response, including sources
export interface SocChatSourceChunk {
  report_id: string;
  source_section: string;
  chunk_id: string;
  // document_preview?: string; // Optional: if we decide to send previews from backend
}

export interface SocChatResponse {
  answer: string;
  source_report_ids?: string[]; // Changed from source_chunks to source_report_ids
}

// Define the structure for the Title generation response
export interface TitleResponse {
  title: string;
}

// Define the structure for the SOC chat filters
export interface SocChatFilters {
  report_id_filter?: string;
  start_date_filter?: string; // Expected format: YYYY-MM-DDTHH:MM:SSZ (ISO 8601)
  end_date_filter?: string;   // Expected format: YYYY-MM-DDTHH:MM:SSZ (ISO 8601)
  ttps_filter?: string;       // Comma-separated string of TTPs
  cves_filter?: string;       // Comma-separated string of CVEs
}

// Define the structure for TTP frequency response
export interface TtpFrequencyData {
  [ttpId: string]: number;
}

export interface TtpFrequencyResponse {
  ttp_frequency: TtpFrequencyData;
  message?: string; // Optional message, e.g., if no data found
}

// Define the structure for report details returned by get-report API
export interface ReportDetails {
  report_id: string;
  chunks: Array<{
    chunk_id: string;
    content: string;
    source_section: string;
    metadata: any;
  }>;
  metadata: any;
  event_summary: string;
  timestamp: number;
  mitre_ttps: string[];
  cves: string[];
}

export function useApi() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  // New state for the multi-report SOC chat
  const [socChatLoading, setSocChatLoading] = useState(false);
  const [socChatError, setSocChatError] = useState<ApiError | null>(null);
  // State for TTP Frequency analysis
  const [ttpFrequencyLoading, setTtpFrequencyLoading] = useState(false);
  const [ttpFrequencyError, setTtpFrequencyError] = useState<ApiError | null>(null);
  
  // State for getting report details
  const [reportDetailsLoading, setReportDetailsLoading] = useState(false);
  const [reportDetailsError, setReportDetailsError] = useState<ApiError | null>(null);
  
  const generateRule = async (prompt: string): Promise<ApiResponse | null> => {
    setLoading(true);
    setError(null);
    
    try {
      // Get API base URL from environment or use localhost as fallback
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';
      
      // Call the backend API
      const response = await fetch(`${API_BASE_URL}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ prompt }),
      });
      
      if (!response.ok) {
        throw new Error(`Error: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      return data;
    } catch (err) {
      const error = err as Error;
      setError({ message: error.message });
      return null;
    } finally {
      setLoading(false);
    }
  };
  
  // New function to generate SOC report
  const generateSocReport = async (alertData: any, systemArchitecture: string): Promise<SocReportResponse | null> => {
    setLoading(true);
    setError(null);

    try {
      // Get API base URL from environment or use localhost as fallback
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';
      
      const response = await fetch(`${API_BASE_URL}/api/generate-soc-report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ alertData, systemArchitecture }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `Error: ${response.status} ${response.statusText}` }));
        throw new Error(errorData.message || `Error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data as SocReportResponse;
    } catch (err) {
      const error = err as Error;
      console.error("Error generating SOC report:", error);
      setError({ message: error.message });
      return null;
    } finally {
      setLoading(false);
    }
  };

  // New function to query the generated report using RAG
  const queryReportRAG = async (userQuery: string, reportContext: string): Promise<RagQueryResponse | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/query-report-rag', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query: userQuery, reportContextString: reportContext }), 
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `Error: ${response.status} ${response.statusText}` }));
        throw new Error(errorData.message || `Error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data as RagQueryResponse;
    } catch (err) {
      const error = err as Error;
      console.error("Error querying report with RAG:", error);
      setError({ message: error.message });
      return null;
    } finally {
      setLoading(false);
    }
  };

  const generateChatTitle = async (userQuery: string, onStream?: (chunk: string) => void): Promise<TitleResponse | null> => {
    try {
      const response = await fetch('/api/generate-chat-title', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_query: userQuery }), 
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `Error: ${response.status} ${response.statusText}` }));
        console.error("Error generating chat title:", errorData.message || `Error: ${response.status} ${response.statusText}`);
        return null;
      }

      // Handle streaming response
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let title = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          const chunk = decoder.decode(value);
          title += chunk;
          onStream?.(chunk);
        }
      }

      return { title };
    } catch (err) {
      const error = err as Error;
      console.error("Error generating chat title:", error);
      return null;
    }
  };

  // New function to chat with the persistent SOC report database
  const chatWithSocReports = async (userQuery: string, filters?: SocChatFilters): Promise<SocChatResponse | null> => {
    setSocChatLoading(true);
    setSocChatError(null);

    try {
      const apiKey = localStorage.getItem('openai_api_key');
      const requestBody = {
        query: userQuery,
        ...(filters && {
          ...(filters.report_id_filter && { report_id_filter: filters.report_id_filter }),
          ...(filters.start_date_filter && { start_date_filter: filters.start_date_filter }),
          ...(filters.end_date_filter && { end_date_filter: filters.end_date_filter }),
          ...(filters.ttps_filter && { ttps_filter: filters.ttps_filter }),
          ...(filters.cves_filter && { cves_filter: filters.cves_filter }),
        })
      };

      // Note: Using relative path for proxy if your dev server is set up for it,
      // otherwise use full path 'http://localhost:5000/api/chat-with-soc-reports'
      const response = await fetch('/api/chat-with-soc-reports', { 
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(apiKey ? { 'X-API-KEY': apiKey } : {}),
        },
        body: JSON.stringify(requestBody), // Send query and filters
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `Error: ${response.status} ${response.statusText}` }));
        throw new Error(errorData.message || `Error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data as SocChatResponse; // Updated to use SocChatResponse interface
    } catch (err) {
      const error = err as Error;
      console.error("Error chatting with SOC reports:", error);
      setSocChatError({ message: error.message });
      return null;
    } finally {
      setSocChatLoading(false);
    }
  };

  // --- New function to get TTP frequency trends ---
  const getTtpFrequency = async (startDate?: string, endDate?: string): Promise<TtpFrequencyResponse | null> => {
    setTtpFrequencyLoading(true);
    setTtpFrequencyError(null);
    try {
      const apiKey = localStorage.getItem('openai_api_key');
      const params = new URLSearchParams();
      if (startDate) params.append('start_date', startDate);
      if (endDate) params.append('end_date', endDate);
      
      const queryString = params.toString();
      const url = `/api/trends/ttp-frequency${queryString ? '?' + queryString : ''}`;

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(apiKey ? { 'X-API-KEY': apiKey } : {}),
        },
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `Error: ${response.status} ${response.statusText}` }));
        throw new Error(errorData.message || `Error: ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      return data as TtpFrequencyResponse;
    } catch (err) {
      const error = err as Error;
      console.error("Error fetching TTP frequency:", error);
      setTtpFrequencyError({ message: error.message });
      return null;
    } finally {
      setTtpFrequencyLoading(false);
    }
  };

  // Function to get report details by ID
  const getReportById = async (reportId: string): Promise<ReportDetails | null> => {
    setReportDetailsLoading(true);
    setReportDetailsError(null);

    try {
      const response = await fetch(`/api/get-report/${reportId}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `Error: ${response.status} ${response.statusText}` }));
        throw new Error(errorData.message || `Error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data as ReportDetails;
    } catch (err) {
      const error = err as Error;
      console.error("Error getting report details:", error);
      setReportDetailsError({ message: error.message });
      return null;
    } finally {
      setReportDetailsLoading(false);
    }
  };

  return {
    loading,
    error,
    socChatLoading, // Expose new loading state
    socChatError,   // Expose new error state
    ttpFrequencyLoading, // Expose TTP frequency loading state
    ttpFrequencyError,   // Expose TTP frequency error state
    reportDetailsLoading, // Expose report details loading state
    reportDetailsError,   // Expose report details error state
    generateRule,
    generateSocReport,
    queryReportRAG, 
    generateChatTitle,
    chatWithSocReports, // Expose the new chat function
    getTtpFrequency,    // Expose the TTP frequency function
    getReportById,       // Expose the getReportById function
  };
}

export default useApi; 