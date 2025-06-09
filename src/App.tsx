import { useState, useEffect } from 'react';
import './App.css';
import ChatInput from './components/ChatInput';
import MessageList from './components/MessageList';
import Sidebar from './components/Sidebar';
import useApi from './hooks/useApi';
import SOCAssistantPage from './pages/SOCAssistant/SOCAssistantPage';
import SOCGlobalChatPage from './pages/SOCGlobalChatPage/SOCGlobalChatPage';
import { AlertTriangleIcon } from 'lucide-react';

type Message = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sigmaRule?: string;
  eqlQuery?: string;
  isTyping?: boolean;
};

type Chat = {
  id: string;
  title: string;
  messages: Message[];
};

// Define types for SOCAssistantPage state
type SocAssistantState = {
  alertFile: File | null;
  alertData: any[] | null;
  socReportContent: any | null;
  // Add other SOCAssistantPage state properties as needed
};

// Define types for SOCGlobalChatPage state
type SocGlobalChatState = {
  messages: any[];
  reportIdFilter: string;
  startDateFilter: string;
  endDateFilter: string;
  ttpsFilter: string;
  cvesFilter: string;
  trendStartDate: string;
  trendEndDate: string;
  ttpFrequencyData: any | null;
  // Add other SOCGlobalChatPage state properties as needed
};

// Placeholder for the new SOC Assistant page
// const SOCAssistantPage = () => (
//   <div className="flex-1 flex flex-col items-center justify-center bg-gray-100">
//     <h1 className="text-2xl font-bold">SOC Assistant Page (Work In Progress)</h1>
//     <p className="mt-2 text-gray-600">File upload and report generation will be here.</p>
//   </div>
// );

function App() {
  // Keep localStorage only for chats and currentView which should persist between reloads
  const [chats, setChats] = useState<Chat[]>(() => {
    const savedChats = localStorage.getItem('siemguardian_chats');
    return savedChats ? JSON.parse(savedChats) : [];
  });
  
  const [currentChatId, setCurrentChatId] = useState<string | null>(null);
  const [currentView, setCurrentView] = useState<'ThreatHunting' | 'SOCAssistant' | 'SOCGlobalChat'>(() => {
    const savedView = localStorage.getItem('siemguardian_currentView');
    if (savedView === 'ThreatHunting' || savedView === 'SOCAssistant' || savedView === 'SOCGlobalChat') {
      return savedView;
    }
    return 'ThreatHunting';
  });
  const { loading, generateRule, generateChatTitle } = useApi();
  const [showApiKeyWarning, setShowApiKeyWarning] = useState(false);
  
  // Keep these states in memory only, no localStorage saving
  const [socAssistantState, setSocAssistantState] = useState<SocAssistantState>({
    alertFile: null,
    alertData: null,
    socReportContent: null,
  });
  
  const [socGlobalChatState, setSocGlobalChatState] = useState<SocGlobalChatState>({
    messages: [],
    reportIdFilter: '',
    startDateFilter: '',
    endDateFilter: '',
    ttpsFilter: '',
    cvesFilter: '',
    trendStartDate: '',
    trendEndDate: '',
    ttpFrequencyData: null,
  });
  
  // Get current chat messages
  const currentChat = chats.find(chat => chat.id === currentChatId);
  const messages = currentChat?.messages || [];
  
  // Save chats to localStorage when they change
  useEffect(() => {
    localStorage.setItem('siemguardian_chats', JSON.stringify(chats));
  }, [chats]);
  
  // Save currentView to localStorage when it changes
  useEffect(() => {
    localStorage.setItem('siemguardian_currentView', currentView);
  }, [currentView]);

  // Remove localStorage saving for SOCAssistant and SOCGlobalChat states
  // This will ensure they are only kept in memory and reset on page reload
  
  // Check if API key exists
  useEffect(() => {
    const apiKey = localStorage.getItem('openai_api_key');
    // Consider key missing if it's null, undefined, or empty string
    const isApiKeyEffectivelyMissing = !apiKey || apiKey.trim() === '';
    setShowApiKeyWarning(isApiKeyEffectivelyMissing);
  }, [currentView]);
  
  // Create a new chat
  const handleNewChat = () => {
    const newChatId = Date.now().toString();
    const newChat: Chat = {
      id: newChatId,
      title: 'New Chat',
      messages: []
    };
    
    setChats(prev => [...prev, newChat]);
    setCurrentChatId(newChatId);
  };
  
  // Select a chat
  const handleSelectChat = (chatId: string) => {
    setCurrentChatId(chatId);
  };
  
  // Delete a chat
  const handleDeleteChat = (chatId: string) => {
    setChats(prev => prev.filter(chat => chat.id !== chatId));
    
    // If we deleted the current chat, select the first available chat
    if (chatId === currentChatId) {
      const remainingChats = chats.filter(chat => chat.id !== chatId);
      if (remainingChats.length > 0) {
        setCurrentChatId(remainingChats[0].id);
      } else {
        handleNewChat();
      }
    }
  };
  
  // Initialize with a new chat if none exists
  useEffect(() => {
    if (chats.length === 0) {
      handleNewChat();
    } else if (!currentChatId) {
      setCurrentChatId(chats[0].id);
    }
  }, [chats, currentChatId]);
  
  const handleSendMessage = async (content: string) => {
    if (!content.trim() || !currentChatId) return;
    
    // Add user message
    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content,
    };
    
    // Determine if this is the first message for title generation for this chat
    const chatForTitleCheck = chats.find(c => c.id === currentChatId);
    const isFirstMeaningfulMessageForTitle = chatForTitleCheck ? chatForTitleCheck.title === 'New Chat' && chatForTitleCheck.messages.length === 0 : false;

    // Update chat messages, initially keeping title or setting to 'New Chat'
    setChats(prev => prev.map(chat => {
      if (chat.id === currentChatId) {
        return {
          ...chat,
          // Title will be updated by AI later if it's the first message
          messages: [...chat.messages, userMessage]
        };
      }
      return chat;
    }));

    // AI Title Generation if it's the first meaningful message
    if (isFirstMeaningfulMessageForTitle && currentChatId) {
      const currentChatIdForTitleUpdate = currentChatId; // Capture currentChatId for async update
      
      // Set initial title as empty and add typing animation class
      setChats(prev => prev.map(chat => {
        if (chat.id === currentChatIdForTitleUpdate) {
          return { ...chat, title: '', isTyping: true };
        }
        return chat;
      }));

      generateChatTitle(content, (chunk) => {
        // Update title with each chunk
        setChats(prev => prev.map(chat => {
          if (chat.id === currentChatIdForTitleUpdate) {
            return { ...chat, title: chat.title + chunk };
          }
          return chat;
        }));
      }).then(titleResponse => {
        if (!titleResponse || !titleResponse.title) {
          // Fallback: if AI title fails, use substring of the first message
          setChats(prev => prev.map(chat => {
            if (chat.id === currentChatIdForTitleUpdate && !chat.title) { // Only update if title is empty
              return { ...chat, title: content.substring(0, 30) + (content.length > 30 ? '...' : ''), isTyping: false };
            }
            return chat;
          }));
        } else {
          // Remove typing animation when done
          setChats(prev => prev.map(chat => {
            if (chat.id === currentChatIdForTitleUpdate) {
              return { ...chat, isTyping: false };
            }
            return chat;
          }));
        }
      });
    }
    
    // Add typing indicator message
    const typingMessage: Message = {
      id: (Date.now() + 1).toString(),
      role: 'assistant',
      content: 'Generating response...',
      isTyping: true,
    };
    
    setChats(prev => prev.map(chat => {
      if (chat.id === currentChatId) {
        return {
          ...chat,
          messages: [...chat.messages, typingMessage]
        };
      }
      return chat;
    }));
    
    try {
      // Generate the rule using our API hook
      const result = await generateRule(content);
      
      // Remove typing indicator
      setChats(prev => prev.map(chat => {
        if (chat.id === currentChatId) {
          return {
            ...chat,
            messages: chat.messages.filter(msg => !msg.isTyping)
          };
        }
        return chat;
      }));
      
      if (result) {
        const assistantMessage: Message = {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: 'Here is a Sigma rule based on your request:',
          sigmaRule: result.sigmaRule,
          eqlQuery: result.eqlQuery,
        };
        
        // Update chat with assistant response
        setChats(prev => prev.map(chat => {
          if (chat.id === currentChatId) {
            return {
              ...chat,
              messages: [...chat.messages, assistantMessage]
            };
          }
          return chat;
        }));
      } else {
        // Add error message
        const errorMessage: Message = {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: 'Sorry, there was an error generating the response. Please try again.',
        };
        
        setChats(prev => prev.map(chat => {
          if (chat.id === currentChatId) {
            return {
              ...chat,
              messages: [...chat.messages, errorMessage]
            };
          }
          return chat;
        }));
      }
    } catch (error) {
      console.error('Error generating response:', error);
      
      // Remove typing indicator
      setChats(prev => prev.map(chat => {
        if (chat.id === currentChatId) {
          return {
            ...chat,
            messages: chat.messages.filter(msg => !msg.isTyping)
          };
        }
        return chat;
      }));
      
      // Add error message
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: 'Sorry, there was an error generating the response. Please try again.',
      };
      
      setChats(prev => prev.map(chat => {
        if (chat.id === currentChatId) {
          return {
            ...chat,
            messages: [...chat.messages, errorMessage]
          };
        }
        return chat;
      }));
    }
  };

  const handleRenameChat = (chatId: string, newTitle: string) => {
    setChats(prev => prev.map(chat => {
      if (chat.id === chatId) {
        return { ...chat, title: newTitle };
      }
      return chat;
    }));
  };

  const handleViewChange = (view: 'ThreatHunting' | 'SOCAssistant' | 'SOCGlobalChat') => {
    setCurrentView(view);
  };

  // Add handlers for SOCAssistant and SOCGlobalChat state updates
  const handleSocAssistantStateChange = (newState: Partial<SocAssistantState>) => {
    setSocAssistantState(prev => ({ ...prev, ...newState }));
  };

  const handleSocGlobalChatStateChange = (newState: Partial<SocGlobalChatState>) => {
    setSocGlobalChatState(prev => ({ ...prev, ...newState }));
  };

  return (
    <div className="flex h-screen">
      <Sidebar 
        onNewChat={handleNewChat}
        chatHistory={chats.map(chat => ({ id: chat.id, title: chat.title }))}
        onSelectChat={handleSelectChat}
        onDeleteChat={handleDeleteChat}
        onRenameChat={handleRenameChat}
        currentView={currentView}
        onViewChange={handleViewChange}
      />
      <main className="flex-1 flex flex-col bg-white relative">
        {currentView === 'ThreatHunting' ? (
          <>
            {showApiKeyWarning ? (
              <div className="flex-1 flex flex-col items-center justify-center p-8">
                <div className="w-full max-w-md p-6 bg-yellow-50 border border-yellow-300 rounded-lg text-sm text-yellow-700 shadow-sm">
                  <div className="flex items-start">
                    <AlertTriangleIcon className="w-5 h-5 mr-3 flex-shrink-0 text-yellow-500 mt-0.5" />
                    <div>
                      <p className="font-semibold text-yellow-800">API Key Missing for Threat Hunting</p>
                      <p className="mt-1">
                        The OpenAI API key is not configured. Threat Hunting features require an API key to function.
                        Please set it up in the application settings or ensure the <code>OPENAI_API_KEY</code> environment variable is available.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ) : messages.length > 0 ? (
          <>
            <div className="flex-1 overflow-y-auto pb-36">
                  <MessageList messages={messages} chatTitle={currentChat?.title} />
            </div>
            <div className="fixed bottom-0 left-64 right-0 bg-gradient-to-t from-white via-white to-transparent py-4">
              <div className="max-w-3xl mx-auto w-full px-8">
                <ChatInput onSendMessage={handleSendMessage} isLoading={loading} />
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="w-full max-w-3xl px-8">
                  <MessageList messages={messages} chatTitle={currentChat?.title} />
              <div className="mt-8">
                <ChatInput onSendMessage={handleSendMessage} isLoading={loading} />
              </div>
            </div>
          </div>
            )}
          </>
        ) : currentView === 'SOCAssistant' ? (
          <SOCAssistantPage 
            initialState={socAssistantState}
            onStateChange={handleSocAssistantStateChange}
          />
        ) : (
          <SOCGlobalChatPage 
            initialState={socGlobalChatState}
            onStateChange={handleSocGlobalChatStateChange}
          />
        )}
      </main>
    </div>
  );
}

export default App;
