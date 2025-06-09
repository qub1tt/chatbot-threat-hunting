import { HistoryIcon, PlusIcon, ShieldIcon, Trash2Icon, PencilIcon, Check, X, MessageSquareTextIcon } from 'lucide-react';
import { useState } from 'react';

interface SidebarProps {
  onNewChat: () => void;
  chatHistory: { id: string; title: string; isTyping?: boolean }[];
  onSelectChat: (id: string) => void;
  onDeleteChat: (id: string) => void;
  onRenameChat: (id: string, newTitle: string) => void;
  currentView: 'ThreatHunting' | 'SOCAssistant' | 'SOCGlobalChat';
  onViewChange: (view: 'ThreatHunting' | 'SOCAssistant' | 'SOCGlobalChat') => void;
}

const Sidebar = ({ onNewChat = () => {}, chatHistory = [], onSelectChat = () => {}, onDeleteChat = () => {}, onRenameChat = () => {}, currentView, onViewChange }: SidebarProps) => {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingTitle, setEditingTitle] = useState('');

  const handleDeleteClick = (e: React.MouseEvent, chatId: string) => {
    e.stopPropagation(); // Prevent triggering the chat selection
    onDeleteChat(chatId);
  };

  const handleEditClick = (e: React.MouseEvent, chatId: string, currentTitle: string) => {
    e.stopPropagation();
    setEditingId(chatId);
    setEditingTitle(currentTitle);
  };

  const handleSaveEdit = (e: React.MouseEvent, chatId: string) => {
    e.stopPropagation();
    if (editingTitle.trim()) {
      onRenameChat(chatId, editingTitle.trim());
    }
    setEditingId(null);
  };

  const handleCancelEdit = (e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingId(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent, chatId: string) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (editingTitle.trim()) {
        onRenameChat(chatId, editingTitle.trim());
        setEditingId(null);
      }
    } else if (e.key === 'Escape') {
      setEditingId(null);
    }
  };

  return (
    <div className="w-64 bg-gray-900 text-white flex flex-col h-full">
      {/* Logo and header */}
      <div className="p-4 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <ShieldIcon className="text-blue-400" />
          <h1 className="text-xl font-bold">SageHunt</h1>
        </div>
        <p className="text-xs text-gray-400 mt-1">AI-Powered Threat Hunting</p>
      </div>
      
      {currentView === 'ThreatHunting' && (
        <>
          {/* New chat button */}
          <div className="p-4">
            <button 
              onClick={onNewChat}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 w-full p-2 rounded-md transition-colors duration-200 cursor-pointer active:scale-95"
            >
              <PlusIcon size={16} />
              <span>New Chat</span>
            </button>
          </div>
          
          {/* History section */}
          <div className="flex-1 overflow-y-auto">
            <div className="p-4">
              <div className="flex items-center text-gray-400 mb-2">
                <HistoryIcon size={16} className="mr-2" />
                <span className="text-sm font-medium">Recent Hunts</span>
              </div>
              <div className="space-y-1">
                {chatHistory.map((chat) => (
                  <div 
                    key={chat.id}
                    className="flex items-center justify-between text-sm py-2 px-3 rounded hover:bg-gray-800 group transition-colors duration-200"
                    onClick={() => editingId !== chat.id && onSelectChat(chat.id)}
                  >
                    {editingId === chat.id ? (
                      <div className="flex-1 flex items-center gap-2">
                        <input
                          type="text"
                          value={editingTitle}
                          onChange={(e) => setEditingTitle(e.target.value)}
                          onKeyDown={(e) => handleKeyDown(e, chat.id)}
                          className="flex-1 bg-gray-700 text-white px-2 py-1 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                          onClick={(e) => e.stopPropagation()}
                          autoFocus
                        />
                        <button
                          onClick={(e) => handleSaveEdit(e, chat.id)}
                          className="text-green-500 hover:text-green-400 cursor-pointer active:scale-95"
                        >
                          <Check size={14} />
                        </button>
                        <button
                          onClick={handleCancelEdit}
                          className="text-red-500 hover:text-red-400 cursor-pointer active:scale-95"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <div className={`flex-1 overflow-hidden text-ellipsis whitespace-nowrap cursor-pointer ${chat.isTyping ? 'typing-title' : ''}`}>
                          {chat.title}
                        </div>
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            className="text-gray-500 hover:text-blue-400 cursor-pointer active:scale-95"
                            onClick={(e) => handleEditClick(e, chat.id, chat.title)}
                          >
                            <PencilIcon size={14} />
                          </button>
                          <button
                            className="text-gray-500 hover:text-red-400 cursor-pointer active:scale-95"
                            onClick={(e) => handleDeleteClick(e, chat.id)}
                          >
                            <Trash2Icon size={14} />
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
      
      {/* View Switcher Section */}
      <div className="p-4 border-t border-gray-800 mt-auto">
        <h3 className="text-xs text-gray-400 uppercase mb-2">Application Mode</h3>
        <div className="space-y-2">
          <button
            onClick={() => onViewChange('ThreatHunting')}
            className={`flex items-center gap-2 w-full p-2 rounded-md transition-colors duration-200 text-sm cursor-pointer
                        ${currentView === 'ThreatHunting' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'}`}
          >
            <ShieldIcon size={16} />
            <span>Threat Hunting</span>
          </button>
          <button
            onClick={() => onViewChange('SOCAssistant')}
            className={`flex items-center gap-2 w-full p-2 rounded-md transition-colors duration-200 text-sm cursor-pointer
                        ${currentView === 'SOCAssistant' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'}`}
          >
            <PencilIcon size={16} />
            <span>Incident Report</span>
          </button>
          <button
            onClick={() => onViewChange('SOCGlobalChat')}
            className={`flex items-center gap-2 w-full p-2 rounded-md transition-colors duration-200 text-sm cursor-pointer
                        ${currentView === 'SOCGlobalChat' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'}`}
          >
            <MessageSquareTextIcon size={16} /> 
            <span>SOC Insights Chat</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;