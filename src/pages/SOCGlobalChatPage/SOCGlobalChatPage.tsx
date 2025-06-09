import React, { useState, useEffect } from 'react';
import MessageList from '../../components/MessageList';
import ChatInput from '../../components/ChatInput';
import TTPFrequencyChart from '../../components/TTPFrequencyChart';
import useApi, { type TtpFrequencyData, type SocChatFilters } from '../../hooks/useApi';
import { MessageSquareTextIcon, BarChart3Icon, AlertTriangleIcon } from 'lucide-react';

// Define your message type (can be shared if identical to other chat messages)
interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  isTyping?: boolean;
  sourceReportIds?: string[]; // Changed from sourceChunks
  // Unlike ThreatHunting chat, these won't typically have sigmaRule or eqlQuery
}

// Define the props for SOCGlobalChatPage
interface SOCGlobalChatPageProps {
  initialState?: {
    messages: ChatMessage[];
    reportIdFilter: string;
    startDateFilter: string;
    endDateFilter: string;
    ttpsFilter: string;
    cvesFilter: string;
    trendStartDate: string;
    trendEndDate: string;
    ttpFrequencyData: TtpFrequencyData | null;
  };
  onStateChange?: (newState: Partial<{
    messages: ChatMessage[];
    reportIdFilter: string;
    startDateFilter: string;
    endDateFilter: string;
    ttpsFilter: string;
    cvesFilter: string;
    trendStartDate: string;
    trendEndDate: string;
    ttpFrequencyData: TtpFrequencyData | null;
  }>) => void;
}

const SOCGlobalChatPage: React.FC<SOCGlobalChatPageProps> = ({ initialState, onStateChange }) => {
  const [messages, setMessages] = useState<ChatMessage[]>(initialState?.messages || []);
  const [showApiKeyWarning, setShowApiKeyWarning] = useState<boolean>(false);
  const {
    chatWithSocReports,
    socChatLoading,
    socChatError,
    getTtpFrequency,
    ttpFrequencyLoading,
    ttpFrequencyError,
  } = useApi();

  // State for filters
  const [reportIdFilter, setReportIdFilter] = useState(initialState?.reportIdFilter || '');
  const [startDateFilter, setStartDateFilter] = useState(initialState?.startDateFilter || '');
  const [endDateFilter, setEndDateFilter] = useState(initialState?.endDateFilter || '');
  const [ttpsFilter, setTtpsFilter] = useState(initialState?.ttpsFilter || '');
  const [cvesFilter, setCvesFilter] = useState(initialState?.cvesFilter || '');

  // State for TTP Trend Analysis
  const [trendStartDate, setTrendStartDate] = useState(initialState?.trendStartDate || '');
  const [trendEndDate, setTrendEndDate] = useState(initialState?.trendEndDate || '');
  const [ttpFrequencyData, setTtpFrequencyData] = useState<TtpFrequencyData | null>(initialState?.ttpFrequencyData || null);

  // Update parent component state when local state changes
  useEffect(() => {
    if (onStateChange) {
      onStateChange({
        messages,
        reportIdFilter,
        startDateFilter,
        endDateFilter,
        ttpsFilter,
        cvesFilter,
        trendStartDate,
        trendEndDate,
        ttpFrequencyData
      });
    }
  }, [
    messages, 
    reportIdFilter, 
    startDateFilter, 
    endDateFilter, 
    ttpsFilter, 
    cvesFilter,
    trendStartDate,
    trendEndDate,
    ttpFrequencyData,
    onStateChange
  ]);

  useEffect(() => {
    // Check for API key on component mount
    const apiKey = localStorage.getItem('openai_api_key');
    if (!apiKey) {
      setShowApiKeyWarning(true);
    }
  }, []);

  const handleSendMessage = async (content: string) => {
    if (!content.trim()) return;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      content,
    };
    // Add user message and a temporary typing indicator for the assistant
    const typingIndicatorId = (Date.now() + 1).toString();
    const assistantTypingMessage: ChatMessage = {
      id: typingIndicatorId,
      role: 'assistant',
      content: 'Assistant is thinking...',
      isTyping: true,
    };
    setMessages(prev => [...prev, userMessage, assistantTypingMessage]);

    const currentFilters: SocChatFilters = {
      ...(reportIdFilter && { report_id_filter: reportIdFilter }),
      ...(startDateFilter && { start_date_filter: startDateFilter ? `${startDateFilter}Z` : undefined }),
      ...(endDateFilter && { end_date_filter: endDateFilter ? `${endDateFilter}Z` : undefined }),
      ...(ttpsFilter && { ttps_filter: ttpsFilter }),
      ...(cvesFilter && { cves_filter: cvesFilter }),
    };

    const response = await chatWithSocReports(content, currentFilters);

    // Remove the typing indicator message
    setMessages(prev => prev.filter(msg => msg.id !== typingIndicatorId));

    if (response && response.answer) {
      const assistantMessage: ChatMessage = {
        id: (Date.now() + 2).toString(), // Ensure unique ID
        role: 'assistant',
        content: response.answer,
        sourceReportIds: response.source_report_ids || [], // Populate sourceReportIds
      };
      setMessages(prev => [...prev, assistantMessage]);
    }
  };

  const handleAnalyzeTtpTrends = async () => {
    setTtpFrequencyData(null); // Clear previous data
    const start = trendStartDate ? `${trendStartDate}Z` : undefined;
    const end = trendEndDate ? `${trendEndDate}Z` : undefined;
    const response = await getTtpFrequency(start, end);
    if (response && response.ttp_frequency) {
      setTtpFrequencyData(response.ttp_frequency);
    } else {
      // Handle no data or error for frequency data (ttpFrequencyError state is already set by useApi)
      console.log(response?.message || "No TTP frequency data returned or error occurred.");
    }
  };

  return (
    <div className="flex flex-col h-full p-4 md:p-6 bg-gray-50 overflow-y-auto">
      <header className="mb-6">
        <h1 className="text-2xl md:text-3xl font-semibold text-gray-800 flex items-center">
          <MessageSquareTextIcon className="w-8 h-8 mr-3 text-blue-600" />
          SOC Insights Chat
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Ask questions about stored SOC reports and explore security event data.
        </p>
      </header>

      {/* API Key Warning Message */}
      {showApiKeyWarning && (
        <div className="mb-4 p-4 bg-yellow-50 border border-yellow-300 rounded-lg text-sm text-yellow-700 shadow-sm w-full" role="alert">
          <div className="flex items-start">
            <AlertTriangleIcon className="w-5 h-5 mr-3 flex-shrink-0 text-yellow-500 mt-0.5" />
            <div>
              <p className="font-semibold text-yellow-800">API Key Missing</p>
              <p className="mt-1">
                The OpenAI API key is not configured. Chat and TTP analysis features may not work as expected.
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

      <div className="flex flex-1 gap-6 overflow-hidden"> {/* Main two-column container */}
        {/* Left Column: Filters and TTP Analysis */}
        <div className="w-1/3 lg:w-1/4 flex flex-col gap-6 overflow-y-auto p-1"> {/* Added p-1 for scrollbar visibility if content overflows */}
          {/* Filter Inputs Section */}
          <div className="p-4 bg-gray-100 rounded-lg shadow">
            <h3 className="text-lg font-semibold text-gray-700 mb-3">Chat Filters</h3>
            <div className="grid grid-cols-1 gap-4"> {/* Simplified grid for filters in a single column */}
              <div>
                <label htmlFor="reportIdFilter" className="block text-sm font-medium text-gray-600 mb-1">Report ID</label>
                <input 
                  type="text" 
                  id="reportIdFilter" 
                  value={reportIdFilter} 
                  onChange={(e) => setReportIdFilter(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="e.g., abc-123..."
                />
              </div>
              <div>
                <label htmlFor="startDateFilter" className="block text-sm font-medium text-gray-600 mb-1">Start Date/Time (Chat)</label>
                <input 
                  type="datetime-local" 
                  id="startDateFilter" 
                  value={startDateFilter} 
                  onChange={(e) => setStartDateFilter(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
              </div>
              <div>
                <label htmlFor="endDateFilter" className="block text-sm font-medium text-gray-600 mb-1">End Date/Time (Chat)</label>
                <input 
                  type="datetime-local" 
                  id="endDateFilter" 
                  value={endDateFilter} 
                  onChange={(e) => setEndDateFilter(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
              </div>
              <div>
                <label htmlFor="ttpsFilter" className="block text-sm font-medium text-gray-600 mb-1">MITRE TTPs (Chat)</label>
                <input 
                  type="text" 
                  id="ttpsFilter" 
                  value={ttpsFilter} 
                  onChange={(e) => setTtpsFilter(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="e.g., T1059,T1071.001"
                />
              </div>
              <div>
                <label htmlFor="cvesFilter" className="block text-sm font-medium text-gray-600 mb-1">CVEs (Chat)</label>
                <input 
                  type="text" 
                  id="cvesFilter" 
                  value={cvesFilter} 
                  onChange={(e) => setCvesFilter(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="e.g., CVE-2023-12345"
                />
              </div>
            </div>
          </div>

          {/* TTP Trend Analysis Section */}
          <div className="p-4 bg-gray-100 rounded-lg shadow">
            <h3 className="text-lg font-semibold text-gray-700 mb-3 flex items-center">
                <BarChart3Icon className="w-6 h-6 mr-2 text-indigo-600" />
                TTP Frequency Analysis
            </h3>
            <div className="grid grid-cols-1 gap-4 items-end"> {/* Simplified grid for TTP controls */}
              <div>
                <label htmlFor="trendStartDate" className="block text-sm font-medium text-gray-600 mb-1">Start Date (Trends)</label>
                <input 
                  type="datetime-local" 
                  id="trendStartDate" 
                  value={trendStartDate} 
                  onChange={(e) => setTrendStartDate(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
              </div>
              <div>
                <label htmlFor="trendEndDate" className="block text-sm font-medium text-gray-600 mb-1">End Date (Trends)</label>
                <input 
                  type="datetime-local" 
                  id="trendEndDate" 
                  value={trendEndDate} 
                  onChange={(e) => setTrendEndDate(e.target.value)} 
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
              </div>
              <div>
                <button 
                  onClick={handleAnalyzeTtpTrends} 
                  disabled={ttpFrequencyLoading}
                  className="w-full mt-1 px-4 py-2 bg-indigo-600 text-white font-semibold rounded-md shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                >
                  {ttpFrequencyLoading ? 'Analyzing...' : 'Analyze TTP Trends'}
                </button>
              </div>
            </div>
            <div className="mt-4">
              <TTPFrequencyChart 
                frequencyData={ttpFrequencyData}
                loading={ttpFrequencyLoading}
                error={ttpFrequencyError?.message || null}
              />
            </div>
          </div>
        </div>

        {/* Right Column: Chat Interface */}
        <div className="flex-1 flex flex-col bg-white shadow rounded-lg overflow-hidden">
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.length === 0 && !socChatLoading && (
              <div className="flex flex-col items-center justify-center h-full text-gray-400">
                <MessageSquareTextIcon size={48} className="mb-4" />
                <p className="text-lg">No messages yet.</p>
                <p className="text-sm">Start by asking a question about your SOC reports.</p>
              </div>
            )}
            {/* Pass messages to MessageList - MessageList will need to be updated to render sourceReportIds */}
            <MessageList messages={messages} showWelcomeMessage={false} />
          </div>

          {/* Enhanced Error Display Section for SOC Chat */}
          {socChatError && (
            <div className="p-3 my-2 mx-4 bg-red-100 border border-red-400 text-red-700 rounded-md text-sm" role="alert">
              <p><span className="font-semibold">Error:</span> {socChatError.message}</p>
              <p className="text-xs mt-1 text-red-600">Please check your query or filters and try again. If the issue persists, ensure the backend is running and the API key is configured correctly.</p>
            </div>
          )}

          <div className="p-4 border-t border-gray-200 bg-gray-50">
            <ChatInput onSendMessage={handleSendMessage} isLoading={socChatLoading} placeholder="Ask about SOC events, reports, or threats..." />
          </div>
        </div>
      </div>
    </div>
  );
};

export default SOCGlobalChatPage; 