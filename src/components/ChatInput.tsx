import { useState, useEffect, useRef } from 'react';
import type { KeyboardEvent, ChangeEvent } from 'react';
import { SendIcon } from 'lucide-react';

interface ChatInputProps {
  onSendMessage: (message: string) => void;
  isLoading: boolean;
  placeholder?: string;
}

const ChatInput = ({ onSendMessage, isLoading, placeholder = "Describe the threat you want to detect..." }: ChatInputProps) => {
  const [input, setInput] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto resize textarea based on content
  useEffect(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      // Reset height to auto to get the correct scrollHeight
      textarea.style.height = 'auto';
      // Set the height to scrollHeight to expand the textarea
      const newHeight = Math.min(textarea.scrollHeight, 300); // Max height of 300px
      textarea.style.height = `${newHeight}px`;
      
      // If content exceeds max height, enable scrolling
      if (textarea.scrollHeight > 300) {
        textarea.style.overflowY = 'auto';
      } else {
        textarea.style.overflowY = 'hidden';
      }
    }
  }, [input]);

  const handleSubmit = () => {
    if (input.trim() && !isLoading) {
      onSendMessage(input);
      setInput('');
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleChange = (e: ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
  };
  
  return (
    <div className="relative w-full">
      <div className="relative bg-white rounded-lg shadow-md border-2 border-gray-300">
        <textarea
          ref={textareaRef}
          className="w-full p-4 pr-12 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none min-h-[60px]"
          placeholder={placeholder}
          value={input}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          rows={1}
        />
        <button
          className="absolute right-3 bottom-3 bg-blue-600 text-white p-2 rounded-lg hover:bg-blue-700 transition-all duration-200 disabled:opacity-50 disabled:hover:bg-blue-600 cursor-pointer active:scale-95"
          onClick={handleSubmit}
          disabled={isLoading || !input.trim()}
        >
          <SendIcon size={20} />
        </button>
      </div>
    </div>
  );
};

export default ChatInput; 