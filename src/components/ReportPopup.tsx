import React, { useState } from 'react';
import { X, Clock, Shield, AlertTriangle, FileText, TerminalIcon, ShieldAlertIcon, WrenchIcon, Download } from 'lucide-react';
import type { ReportDetails } from '../hooks/useApi';

interface ReportPopupProps {
  reportId: string;
  reportDetails: ReportDetails | null;
  isLoading: boolean;
  error: string | null;
  onClose: () => void;
}

const ReportPopup: React.FC<ReportPopupProps> = ({
  reportId,
  reportDetails,
  isLoading,
  error,
  onClose
}) => {
  const [isDownloading, setIsDownloading] = useState(false);

  // Format timestamp
  const formatTimestamp = (timestamp: number): string => {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp * 1000).toLocaleString();
  };

  // Handle backdrop click
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Handle PDF download
  const handleDownloadPDF = async () => {
    const report = reconstructReport();
    if (!report) return;
    
    setIsDownloading(true);
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';
      const response = await fetch(`${API_BASE_URL}/api/download-report-pdf`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(report),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // Get the filename from response headers
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = 'SOC_Incident_Report.pdf';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading PDF:', error);
      alert('Failed to download PDF. Please try again.');
    } finally {
      setIsDownloading(false);
    }
  };

  // Reconstruct the original report structure from chunks
  const reconstructReport = () => {
    if (!reportDetails?.chunks) return null;

    const report: any = {
      eventSummary: '',
      technicalAnalysis: '',
      defensiveRules: { description: '', rules: [] },
      systemRemediation: '',
      mitreAttackTable: []
    };

    reportDetails.chunks.forEach(chunk => {
      switch (chunk.source_section) {
        case 'Event Summary':
          report.eventSummary = chunk.content;
          break;
        case 'Technical Analysis':
        case 'Technical Analysis - Paragraph 1':
        case 'Technical Analysis - Paragraph 2':
        case 'Technical Analysis - Paragraph 3':
        case 'Technical Analysis - Paragraph 4':
        case 'Technical Analysis - Paragraph 5':
          // Combine all technical analysis paragraphs
          if (report.technicalAnalysis) {
            report.technicalAnalysis += '\n\n' + chunk.content;
          } else {
            report.technicalAnalysis = chunk.content;
          }
          break;
        case 'Defensive Rules - Summary':
          report.defensiveRules.description = chunk.content;
          break;
        case 'Defensive Rule 1':
        case 'Defensive Rule 2':
        case 'Defensive Rule 3':
        case 'Defensive Rule 4':
        case 'Defensive Rule 5':
          // Parse defensive rule content
          try {
            const ruleText = chunk.content;
            const typeMatch = ruleText.match(/Type:\s*([^,]+)/);
            const contentMatch = ruleText.match(/Content:\s*([^,]+(?:,[^,]*)*?)(?:,\s*Description:|$)/);
            const descMatch = ruleText.match(/Description:\s*(.+)$/);
            
            if (typeMatch && contentMatch) {
              report.defensiveRules.rules.push({
                type: typeMatch[1].trim(),
                content: contentMatch[1].trim(),
                description: descMatch ? descMatch[1].trim() : ''
              });
            }
          } catch (e) {
            console.error('Error parsing defensive rule:', e);
          }
          break;
        case 'System Remediation':
          report.systemRemediation = chunk.content;
          break;
        case 'mitreAttackTable':
          try {
            report.mitreAttackTable = JSON.parse(chunk.content);
          } catch (e) {
            console.error('Error parsing MITRE ATT&CK table:', e);
          }
          break;
      }
    });

    return report;
  };

  const renderRuleContent = (rule: any) => {
    return (
      <div key={rule.type + rule.content.slice(0,20)} className='mb-3 p-3 bg-slate-50 rounded border border-gray-200'>
        <p className='text-xs font-semibold text-indigo-600 mb-1 capitalize'>{rule.type} Rule:</p>
        {rule.description && <p className='text-xs text-gray-500 mb-1'>{rule.description}</p>}
        <pre className='bg-gray-800 text-white p-2 rounded text-xs overflow-x-auto whitespace-pre-wrap break-all'>{rule.content}</pre>
      </div>
    );
  };

  const reconstructedReport = reconstructReport();

  return (
    <div 
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onClick={handleBackdropClick}
    >
      <div className="bg-white rounded-lg shadow-xl max-w-5xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 bg-gray-50">
          <div className="flex items-center space-x-3">
            <FileText className="w-6 h-6 text-blue-600" />
            <div>
              <h2 className="text-xl font-semibold text-gray-800">SOC Incident Report</h2>
              <p className="text-sm text-gray-600">Report ID: {reportId}</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {/* Download PDF Button */}
            {reportDetails && !isLoading && !error && (
              <button
                onClick={handleDownloadPDF}
                disabled={isDownloading}
                                 className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-lg transition-colors cursor-pointer disabled:cursor-not-allowed"
              >
                {isDownloading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    <span className="text-sm">Downloading...</span>
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4" />
                    <span className="text-sm">Download PDF</span>
                  </>
                )}
              </button>
            )}
            {/* Close Button */}
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-200 rounded-full transition-colors"
            >
              <X className="w-5 h-5 text-gray-500" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(90vh-120px)]">
          {isLoading && (
            <div className="flex items-center justify-center p-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <span className="ml-3 text-gray-600">Loading report details...</span>
            </div>
          )}

          {error && (
            <div className="p-6">
              <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                <div className="flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  <span className="font-semibold">Error:</span>
                </div>
                <p className="mt-1">{error}</p>
              </div>
            </div>
          )}

          {reportDetails && reconstructedReport && !isLoading && !error && (
            <div className="p-6">
              {/* Report Metadata */}
              <div className="mb-6 p-4 bg-gray-50 rounded-lg">
                <h3 className="text-lg font-semibold text-gray-800 mb-3 flex items-center">
                  <Shield className="w-5 h-5 mr-2 text-blue-600" />
                  Report Overview
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div className="flex items-center">
                    <Clock className="w-4 h-4 mr-2 text-gray-500" />
                    <span className="font-medium">Timestamp:</span>
                    <span className="ml-2 text-gray-600">{formatTimestamp(reportDetails.timestamp)}</span>
                  </div>
                  {reportDetails.mitre_ttps && reportDetails.mitre_ttps.length > 0 && (
                    <div>
                      <span className="font-medium">MITRE TTPs:</span>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {reportDetails.mitre_ttps.map((ttp, index) => (
                          <span key={index} className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-xs">
                            {ttp}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {reportDetails.cves && reportDetails.cves.length > 0 && (
                    <div>
                      <span className="font-medium">CVEs:</span>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {reportDetails.cves.map((cve, index) => (
                          <span key={index} className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs">
                            {cve}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Report Content - Structured like SOC Assistant */}
              <div className="space-y-6">
                {/* I. Event Summary */}
                {reconstructedReport.eventSummary && (
                  <div className="p-4 border border-gray-200 rounded-md bg-slate-50">
                    <h3 className="text-lg font-semibold text-slate-700 mb-2 flex items-center">
                      <FileText className='w-5 h-5 mr-2 text-slate-500'/>
                      I. Event Summary
                    </h3>
                    <p className="text-sm text-gray-700 whitespace-pre-wrap">{reconstructedReport.eventSummary}</p>
                  </div>
                )}

                {/* II. Technical Analysis */}
                {reconstructedReport.technicalAnalysis && (
                  <div className="p-4 border border-gray-200 rounded-md bg-slate-50">
                    <h3 className="text-lg font-semibold text-slate-700 mb-2 flex items-center">
                      <TerminalIcon className='w-5 h-5 mr-2 text-slate-500'/>
                      II. Technical Analysis
                    </h3>
                    <p className="text-sm text-gray-700 whitespace-pre-wrap">{reconstructedReport.technicalAnalysis}</p>
                  </div>
                )}

                {/* III. Defensive Rules */}
                {(reconstructedReport.defensiveRules.description || reconstructedReport.defensiveRules.rules.length > 0) && (
                  <div className="p-4 border border-gray-200 rounded-md bg-slate-50">
                    <h3 className="text-lg font-semibold text-slate-700 mb-2 flex items-center">
                      <ShieldAlertIcon className='w-5 h-5 mr-2 text-slate-500'/>
                      III. Defensive Rules
                    </h3>
                    {reconstructedReport.defensiveRules.description && (
                      <p className="text-sm text-gray-700 mb-3 whitespace-pre-wrap">{reconstructedReport.defensiveRules.description}</p>
                    )}
                    {reconstructedReport.defensiveRules.rules && reconstructedReport.defensiveRules.rules.length > 0 ? (
                      reconstructedReport.defensiveRules.rules.map(renderRuleContent)
                    ) : (
                      <p className='text-sm text-gray-500 italic'>No specific rules were generated for this event.</p>
                    )}
                  </div>
                )}

                {/* IV. System Remediation */}
                {reconstructedReport.systemRemediation && (
                  <div className="p-4 border border-gray-200 rounded-md bg-slate-50">
                    <h3 className="text-lg font-semibold text-slate-700 mb-2 flex items-center">
                      <WrenchIcon className='w-5 h-5 mr-2 text-slate-500'/>
                      IV. System Remediation Recommendations
                    </h3>
                    <p className="text-sm text-gray-700 whitespace-pre-wrap">{reconstructedReport.systemRemediation}</p>
                  </div>
                )}

                {/* V. MITRE ATT&CK Table */}
                {reconstructedReport.mitreAttackTable && reconstructedReport.mitreAttackTable.length > 0 && (
                  <div className="p-4 border border-gray-200 rounded-md bg-slate-50">
                    <h3 className="text-lg font-semibold text-slate-700 mb-3 flex items-center">
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
                          {reconstructedReport.mitreAttackTable.map((technique: any, index: number) => (
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
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportPopup; 