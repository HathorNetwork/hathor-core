'use client';

import React, { useState, useEffect, useRef } from 'react';
import { MessageSquare, X, Send, Lightbulb, ChevronLeft, ChevronRight } from 'lucide-react';
import { useIDEStore } from '@/store/ide-store';
import { aiApi } from '@/lib/api';
import { storage } from '@/lib/storage';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { DiffViewer } from './DiffViewer';

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  suggestions?: string[];
  originalCode?: string;
  modifiedCode?: string;
}

interface AIAssistantProps {
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

export const AIAssistant: React.FC<AIAssistantProps> = ({ isCollapsed, onToggleCollapse }) => {
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { 
    files, 
    activeFileId, 
    consoleMessages, 
    updateFile, 
    chatSessions,
    activeChatSessionId,
    createChatSession,
    addChatMessage,
    getChatSession,
    setActiveChatSession 
  } = useIDEStore();

  const activeFile = files.find(f => f.id === activeFileId);

  // Get current chat session, creating one if needed
  const currentChatSession = getChatSession(activeChatSessionId || '') || null;
  const messages: Message[] = currentChatSession ? currentChatSession.messages.map(msg => ({
    id: msg.id,
    type: msg.role === 'user' ? 'user' : 'assistant',
    content: msg.content,
    timestamp: new Date(msg.timestamp),
    suggestions: msg.suggestions,
    originalCode: msg.originalCode,
    modifiedCode: msg.modifiedCode
  })) : [];

  // Ensure there's always an active chat session
  useEffect(() => {
    if (!activeChatSessionId || !getChatSession(activeChatSessionId)) {
      createChatSession();
    }
  }, [activeChatSessionId, createChatSession, getChatSession]);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isLoading || !activeChatSessionId) return;

    const userMessage = {
      id: Date.now().toString(),
      role: 'user' as const,
      content: inputMessage.trim(),
      timestamp: Date.now()
    };

    addChatMessage(activeChatSessionId, userMessage);
    setInputMessage('');
    setIsLoading(true);

    try {
      // Prepare context for the AI
      const recentConsoleMessages = consoleMessages
        .slice(-5)
        .map(msg => `[${msg.type.toUpperCase()}] ${msg.message}`);

      // Convert recent messages to conversation history (last 6 messages)
      const conversationHistory = messages
        .slice(-6)
        .map(msg => ({
          role: msg.type === 'user' ? 'user' as const : 'assistant' as const,
          content: msg.content
        }));

      const response = await aiApi.chat({
        message: inputMessage.trim(),
        current_file_content: activeFile?.content,
        current_file_name: activeFile?.name,
        console_messages: recentConsoleMessages,
        conversation_history: conversationHistory,
        context: {
          total_files: files.length,
          has_compiled_contracts: consoleMessages.some(msg => msg.message.includes('compiled')),
          recent_errors: consoleMessages.filter(msg => msg.type === 'error').length
        }
      });

      // Debug logging to see what we're getting from the backend
      console.log('AI Response:', {
        hasOriginalCode: !!response.original_code,
        hasModifiedCode: !!response.modified_code,
        originalCodeLength: response.original_code?.length,
        modifiedCodeLength: response.modified_code?.length,
        messagePreview: response.message.substring(0, 100)
      });

      const assistantMessage = {
        id: (Date.now() + 1).toString(),
        role: 'assistant' as const,
        content: response.message,
        timestamp: Date.now(),
        suggestions: response.suggestions,
        originalCode: response.original_code,
        modifiedCode: response.modified_code
      };

      addChatMessage(activeChatSessionId, assistantMessage);

    } catch (error) {
      const errorMessage = {
        id: (Date.now() + 1).toString(),
        role: 'assistant' as const,
        content: "Sorry, I'm having trouble right now! 😅 But I'm still here to help with general nano contract questions!",
        timestamp: Date.now(),
        suggestions: [
          "Check your nano contract syntax",
          "Ensure proper method decorators",
          "Review the Hathor documentation"
        ]
      };

      if (activeChatSessionId) {
        addChatMessage(activeChatSessionId, errorMessage);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSuggestionClick = (suggestion: string) => {
    setInputMessage(suggestion);
  };

  const handleApplyDiff = (modifiedCode: string, messageId: string) => {
    if (activeFileId && activeFile && activeChatSessionId) {
      updateFile(activeFileId, modifiedCode);
      // Update the message in the chat session to remove the diff
      const session = getChatSession(activeChatSessionId);
      if (session) {
        const updatedSession = {
          ...session,
          messages: session.messages.map(msg =>
            msg.id === messageId 
              ? { ...msg, originalCode: undefined, modifiedCode: undefined } 
              : msg
          ),
          lastModified: Date.now()
        };
        // Save the updated session directly to storage
        storage.saveChatSession(updatedSession).catch(console.error);
        // Update the store
        useIDEStore.setState(state => ({
          chatSessions: state.chatSessions.map(s => s.id === activeChatSessionId ? updatedSession : s)
        }));
      }
    }
  };

  const handleRejectDiff = (messageId: string) => {
    if (activeChatSessionId) {
      const session = getChatSession(activeChatSessionId);
      if (session) {
        const updatedSession = {
          ...session,
          messages: session.messages.map(msg =>
            msg.id === messageId 
              ? { ...msg, originalCode: undefined, modifiedCode: undefined } 
              : msg
          ),
          lastModified: Date.now()
        };
        // Save the updated session directly to storage
        storage.saveChatSession(updatedSession).catch(console.error);
        // Update the store
        useIDEStore.setState(state => ({
          chatSessions: state.chatSessions.map(s => s.id === activeChatSessionId ? updatedSession : s)
        }));
      }
    }
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
              className={`inline-block max-w-full p-3 rounded-lg text-sm ${message.type === 'user'
                ? 'bg-blue-600 text-white ml-8'
                : 'bg-gray-700 text-gray-100 mr-8'
                }`}
            >
              {message.type === 'assistant' ? (
                <div className="text-sm leading-relaxed">
                  <ReactMarkdown
                    components={{
                      pre: ({ children }) => {
                        const only = Array.isArray(children) ? children[0] : children;
                        const text = only?.props?.children;
                        if (typeof text === 'string' && !text.includes('\n') && text.length < 80) {
                          return (
                            <code className="bg-gray-800 text-blue-300 px-2 py-1 rounded-md text-xs font-mono border border-gray-600">
                              {text}
                            </code>
                          );
                        }
                        
                        // For multi-line code blocks, use syntax highlighting
                        const match = /language-(\w+)/.exec(only?.props?.className || '');
                        const language = match ? match[1] : 'python';
                        
                        return (
                          <SyntaxHighlighter
                            style={vscDarkPlus}
                            language={language}
                            PreTag="div"
                            className="text-xs rounded-lg my-2"
                            customStyle={{
                              margin: '0.5rem 0',
                              borderRadius: '0.5rem',
                              fontSize: '0.75rem',
                            }}
                          >
                            {String(text).replace(/\n$/, '')}
                          </SyntaxHighlighter>
                        );
                      },
                      code: ({ inline, children, ...props }) =>
                        inline ? (
                          <code className="bg-gray-800 text-blue-300 px-2 py-1 rounded-md text-xs font-mono border border-gray-600" {...props}>
                            {children}
                          </code>
                        ) : (
                          <code className="bg-gray-800 text-blue-300 px-2 py-1 rounded-md text-xs font-mono border border-gray-600" {...props}>{children}</code>
                        ),
                    }}
                  >
                    {message.content}
                  </ReactMarkdown>
                </div>
              ) : (
                <div className="whitespace-pre-wrap">{message.content}</div>
              )}

              {/* Diff Viewer */}
              {message.originalCode && message.modifiedCode && activeFile && (
                <div className="mt-3">
                  <DiffViewer
                    originalCode={message.originalCode}
                    modifiedCode={message.modifiedCode}
                    fileName={activeFile.name}
                    onApply={(modifiedCode) => handleApplyDiff(modifiedCode, message.id)}
                    onReject={() => handleRejectDiff(message.id)}
                  />
                </div>
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
