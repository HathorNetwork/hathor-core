'use client';

import React, { useState, useEffect, useRef } from 'react';
import { MessageSquare, X, Send, Lightbulb, ChevronLeft, ChevronRight } from 'lucide-react';
import { useIDEStore } from '@/store/ide-store';
import { aiApi } from '@/lib/api';
import ReactMarkdown from 'react-markdown';

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  suggestions?: string[];
}

interface AIAssistantProps {
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

export const AIAssistant: React.FC<AIAssistantProps> = ({ isCollapsed, onToggleCollapse }) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { files, activeFileId, consoleMessages } = useIDEStore();

  const activeFile = files.find(f => f.id === activeFileId);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: inputMessage.trim(),
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);

    try {
      // Prepare context for the AI
      const recentConsoleMessages = consoleMessages
        .slice(-5)
        .map(msg => `[${msg.type.toUpperCase()}] ${msg.message}`);

      const response = await aiApi.chat({
        message: inputMessage.trim(),
        current_file_content: activeFile?.content,
        current_file_name: activeFile?.name,
        console_messages: recentConsoleMessages,
        context: {
          total_files: files.length,
          has_compiled_contracts: consoleMessages.some(msg => msg.message.includes('compiled')),
          recent_errors: consoleMessages.filter(msg => msg.type === 'error').length
        }
      });

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: response.message,
        timestamp: new Date(),
        suggestions: response.suggestions
      };

      setMessages(prev => [...prev, assistantMessage]);

    } catch (error) {
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: "Sorry, I'm having trouble right now! 😅 But I'm still here to help with general nano contract questions!",
        timestamp: new Date(),
        suggestions: [
          "Check your nano contract syntax",
          "Ensure proper method decorators",
          "Review the Hathor documentation"
        ]
      };

      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSuggestionClick = (suggestion: string) => {
    setInputMessage(suggestion);
  };

  if (isCollapsed) {
    return (
      <div className="h-full bg-gray-800 border-l border-gray-700 flex items-center justify-center">
        <button
          onClick={onToggleCollapse}
          className="p-2 text-gray-400 hover:text-white transition-colors"
          title="Expand AI Assistant"
        >
          <ChevronLeft size={20} />
        </button>
      </div>
    );
  }

  return (
    <div className="h-full bg-gray-800 border-l border-gray-700 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-3 bg-gray-900 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <MessageSquare size={16} className="text-blue-400" />
          <span className="font-semibold text-sm text-white">AI Assistant</span>
        </div>
        <button
          onClick={onToggleCollapse}
          className="p-1 text-gray-400 hover:text-white transition-colors"
          title="Collapse"
        >
          <ChevronRight size={16} />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-3 bg-gray-800">
        {messages.length === 0 && (
          <div className="text-center text-gray-400 text-sm mt-8">
            <div className="mb-2">🤖</div>
            <p>Hi! I'm your Hathor AI assistant!</p>
            <p className="text-xs mt-1">Ask me about nano contracts, debugging, or best practices!</p>
          </div>
        )}

        {messages.map((message) => (
          <div
            key={message.id}
            className={`mb-4 ${message.type === 'user' ? 'text-right' : 'text-left'}`}
          >
            <div
              className={`inline-block max-w-full p-3 rounded-lg text-sm ${
                message.type === 'user'
                  ? 'bg-blue-600 text-white ml-8'
                  : 'bg-gray-700 text-gray-100 mr-8'
              }`}
            >
              {message.type === 'assistant' ? (
                <div className="prose prose-sm prose-invert max-w-none">
                  <ReactMarkdown
                    components={{
                      code: ({ node, inline, className, children, ...props }) => {
                        return inline ? (
                          <code className="bg-gray-600 px-1 py-0.5 rounded text-xs" {...props}>
                            {children}
                          </code>
                        ) : (
                          <pre className="bg-gray-900 p-2 rounded overflow-x-auto">
                            <code className="text-xs" {...props}>
                              {children}
                            </code>
                          </pre>
                        );
                      },
                      p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                      ul: ({ children }) => <ul className="list-disc list-inside mb-2">{children}</ul>,
                      ol: ({ children }) => <ol className="list-decimal list-inside mb-2">{children}</ol>,
                      li: ({ children }) => <li className="mb-1">{children}</li>,
                      h1: ({ children }) => <h1 className="text-lg font-bold mb-2">{children}</h1>,
                      h2: ({ children }) => <h2 className="text-base font-bold mb-2">{children}</h2>,
                      h3: ({ children }) => <h3 className="text-sm font-bold mb-1">{children}</h3>,
                    }}
                  >
                    {message.content}
                  </ReactMarkdown>
                </div>
              ) : (
                <div className="whitespace-pre-wrap">{message.content}</div>
              )}
              
              {/* Suggestions */}
              {message.suggestions && message.suggestions.length > 0 && (
                <div className="mt-3 space-y-1">
                  <div className="flex items-center gap-1 text-xs text-gray-400 mb-2">
                    <Lightbulb size={12} />
                    <span>Suggestions:</span>
                  </div>
                  {message.suggestions.map((suggestion, index) => (
                    <button
                      key={index}
                      onClick={() => handleSuggestionClick(suggestion)}
                      className="block w-full text-left px-2 py-1 text-xs bg-gray-600 hover:bg-gray-500 border border-gray-600 rounded text-gray-200 transition-colors"
                    >
                      💡 {suggestion}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {message.timestamp.toLocaleTimeString()}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="text-left mb-3">
            <div className="inline-block bg-gray-700 rounded-lg p-3 mr-8">
              <div className="flex items-center gap-2 text-sm text-gray-300">
                <div className="animate-spin w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full"></div>
                AI is thinking...
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-3 border-t border-gray-700 bg-gray-900">
        <div className="flex gap-2">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Ask about nano contracts..."
            className="flex-1 px-3 py-2 text-sm bg-gray-700 text-white border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            disabled={isLoading}
          />
          <button
            onClick={handleSendMessage}
            disabled={!inputMessage.trim() || isLoading}
            className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            title="Send message"
          >
            <Send size={16} />
          </button>
        </div>

        {/* Current file indicator */}
        {activeFile && (
          <div className="mt-2 text-xs text-gray-400 flex items-center gap-1">
            📄 Currently viewing: <span className="text-gray-300">{activeFile.name}</span>
          </div>
        )}
      </div>
    </div>
  );
};