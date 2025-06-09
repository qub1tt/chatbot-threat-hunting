import { Copy, Check, BookOpenIcon, Download } from 'lucide-react';
import { useState, useEffect } from 'react';
import useApi from '../hooks/useApi';
import type { ReportDetails } from '../hooks/useApi';
import ReportPopup from './ReportPopup';

// Definition for source chunks (mirrors what's expected from useApi.ts/SOCGlobalChatPage.tsx)
// This interface is no longer needed here as we switched to sourceReportIds
// interface SocChatSourceChunk {
//   report_id: string;
//   source_section: string;
//   chunk_id: string;
// }

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sigmaRule?: string;
  eqlQuery?: string;
  isTyping?: boolean;
  sourceReportIds?: string[]; // Changed from sourceChunks
}

interface MessageListProps {
  messages: Message[];
  showWelcomeMessage?: boolean;
  chatTitle?: string;
}

const MessageList = ({ messages, showWelcomeMessage = true, chatTitle }: MessageListProps) => {
  const [copiedStates, setCopiedStates] = useState<{[key: string]: boolean}>({});
  const [displayContent, setDisplayContent] = useState<{[key: string]: string}>({});
  
  // State for report popup
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [reportDetails, setReportDetails] = useState<ReportDetails | null>(null);
  const [showReportPopup, setShowReportPopup] = useState(false);
  
  // Get API functions
  const { getReportById, reportDetailsLoading, reportDetailsError } = useApi();

  useEffect(() => {
    // Initialize display content for new messages
    messages.forEach(message => {
      if (!displayContent[message.id] && message.role === 'assistant' && !message.isTyping) {
        setDisplayContent(prev => ({
          ...prev,
          [message.id]: ''
        }));
        
        // Start typing effect for assistant messages
        let i = 0;
        const content = message.content;
        const interval = setInterval(() => {
          if (i <= content.length) {
            setDisplayContent(prev => ({
              ...prev,
              [message.id]: content.substring(0, i)
            }));
            i++;
          } else {
            clearInterval(interval);
          }
        }, 15); // Speed of typing animation
        
        return () => clearInterval(interval);
      }
    });
  }, [messages]);

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedStates({ ...copiedStates, [id]: true });
      setTimeout(() => {
        setCopiedStates(prev => ({ ...prev, [id]: false }));
      }, 2000);
    } catch (err) {
      console.error('Failed to copy text:', err);
    }
  };

  const handleDownloadRule = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Handle report ID click
  const handleReportClick = async (reportId: string) => {
    setSelectedReportId(reportId);
    setShowReportPopup(true);
    setReportDetails(null); // Reset previous data
    
    // Fetch report details
    const details = await getReportById(reportId);
    if (details) {
      setReportDetails(details);
    }
  };

  // Handle closing the popup
  const handleClosePopup = () => {
    setShowReportPopup(false);
    setSelectedReportId(null);
    setReportDetails(null);
  };

  const generateFilenameFromTitle = (title: string | undefined): string => {
    if (!title || title.trim() === '' || title.toLowerCase() === 'new chat') {
      return 'sigma_rule.yml'; // Default filename
    }
    const sanitizedTitle = title
      .toLowerCase()
      .replace(/\s+/g, '_') // Replace spaces with underscores
      .replace(/[^a-z0-9_]/g, '') // Remove special characters
      .substring(0, 30); // Truncate to 30 chars
    return `${sanitizedTitle || 'sigma_rule'}.yml`;
  };

  if (messages.length === 0 && showWelcomeMessage) {
    return (
      <div className="text-center">
        <h2 className="text-4xl font-bold mb-4 text-gray-800">Welcome to SageHunt</h2>
        <p className="text-xl text-gray-600">Your AI-powered Threat Hunting Assistant</p>
      </div>
    );
  }

  return (
    <div className="w-full">
      <div className="max-w-3xl mx-auto">
        {messages.map((message, index) => (
          <div
            key={message.id}
            className={`p-4 animate-fade-in`}
            style={{
              animationDelay: `${index * 100}ms`,
            }}
          >
            <div className={`max-w-[85%] ${message.role === 'user' ? 'ml-auto' : ''}`}>
              <div className={`rounded-2xl p-4 ${
                message.role === 'user' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-100 text-gray-800'
              }`}>
                <div className="whitespace-pre-wrap">
                  {message.role === 'assistant' && !message.isTyping 
                    ? displayContent[message.id] || '' 
                    : message.content}
                  {message.isTyping && (
                    <span className="inline-block ml-1 animate-pulse">▋</span>
                  )}
                </div>
              </div>
              
              {message.sigmaRule && !message.isTyping && (
                <div className="mt-4 animate-slide-up bg-gray-100 rounded-2xl p-4" style={{ animationDelay: '200ms' }}>
                  <div className="flex justify-between items-center text-sm font-medium text-gray-500 mb-1">
                    <span>Sigma Rule:</span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleDownloadRule(message.sigmaRule!, generateFilenameFromTitle(chatTitle))}
                        className="flex items-center gap-1 text-gray-500 hover:text-gray-700 transition-colors cursor-pointer active:scale-95"
                      >
                        <Download size={16} />
                        <span>Download</span>
                      </button>
                    <button
                      onClick={() => handleCopy(message.sigmaRule!, `sigma-${message.id}`)}
                      className={`flex items-center gap-1 text-gray-500 hover:text-gray-700 transition-colors cursor-pointer ${
                        copiedStates[`sigma-${message.id}`] ? '' : 'active:scale-95'
                      }`}
                    >
                      {copiedStates[`sigma-${message.id}`] ? (
                        <>
                          <Check size={16} className="text-green-500" />
                          <span className="text-green-500">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy size={16} />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                    </div>
                  </div>
                  <pre className="bg-gray-800 text-green-400 p-3 rounded-lg overflow-x-auto text-sm">
                    {message.sigmaRule}
                  </pre>
                </div>
              )}
              
              {message.eqlQuery && !message.isTyping && (
                <div className="mt-4 animate-slide-up bg-gray-100 rounded-2xl p-4" style={{ animationDelay: '300ms' }}>
                  <div className="flex justify-between items-center text-sm font-medium text-gray-500 mb-1">
                    <span>EQL Query for ELK:</span>
                    <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(message.eqlQuery!, `eql-${message.id}`)}
                      className={`flex items-center gap-1 text-gray-500 hover:text-gray-700 transition-colors cursor-pointer ${
                        copiedStates[`eql-${message.id}`] ? '' : 'active:scale-95'
                      }`}
                    >
                      {copiedStates[`eql-${message.id}`] ? (
                        <>
                          <Check size={16} className="text-green-500" />
                          <span className="text-green-500">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy size={16} />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                    </div>
                  </div>
                  <pre className="bg-gray-800 text-yellow-400 p-3 rounded-lg overflow-x-auto text-sm">
                    {message.eqlQuery}
                  </pre>
                </div>
              )}

              {/* Display Source Report IDs for Assistant Messages */}
              {message.role === 'assistant' && message.sourceReportIds && message.sourceReportIds.length > 0 && !message.isTyping && (
                <div className="mt-3 pt-3 border-t border-gray-200 animate-slide-up" style={{ animationDelay: '400ms' }}>
                  <h4 className="text-xs font-semibold text-gray-500 mb-1.5 flex items-center">
                    <BookOpenIcon size={14} className="mr-1.5 text-gray-400" />
                    Source Reports:
                  </h4>
                  <ul className="list-none pl-0 space-y-1">
                    {message.sourceReportIds.map((reportId, idx) => (
                      <li key={idx} className="text-xs">
                        <button
                          onClick={() => handleReportClick(reportId)}
                          className="text-blue-600 hover:text-blue-800 hover:bg-blue-50 bg-gray-50 p-1.5 rounded transition-colors cursor-pointer border border-transparent hover:border-blue-200"
                        >
                          Report ID: <span className="font-medium">{reportId}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
      
      {/* Report Popup */}
      {showReportPopup && selectedReportId && (
        <ReportPopup
          reportId={selectedReportId}
          reportDetails={reportDetails}
          isLoading={reportDetailsLoading}
          error={reportDetailsError?.message || null}
          onClose={handleClosePopup}
        />
      )}
    </div>
  );
};

export default MessageList; 