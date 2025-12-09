import React, { useState, useRef, useEffect } from 'react';
import { MessageCircle, X, Send, Minimize2, Maximize2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { useSettingsStore } from '@stores/settingsStore';
import { getThemeStyles } from '../../utils/themeStyles';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface FloatingChatProps {
  onSendMessage: (message: string, context: Message[]) => Promise<string>;
}

const FloatingChat: React.FC<FloatingChatProps> = ({ onSendMessage }) => {
  const { currentColors } = useSettingsStore();
  const themeStyles = getThemeStyles(currentColors);

  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!inputValue.trim() || isLoading) return;

    const userMessage: Message = {
      role: 'user',
      content: inputValue,
    };

    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setIsLoading(true);

    try {
      const response = await onSendMessage(inputValue, messages);
      const assistantMessage: Message = {
        role: 'assistant',
        content: response,
      };
      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      const errorMessage: Message = {
        role: 'assistant',
        content: 'Erro ao processar sua mensagem. Tente novamente.',
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 bg-blue-600 hover:bg-blue-700 text-white rounded-full p-4 shadow-lg transition-all duration-200 hover:scale-110 z-50"
      >
        <MessageCircle size={24} />
      </button>
    );
  }

  return (
    <div
      className={`fixed bottom-6 right-6 rounded-lg shadow-2xl z-50 flex flex-col transition-all duration-300 ${
        isMinimized ? 'w-80 h-16' : 'w-96 h-[600px]'
      }`}
      style={{
        backgroundColor: currentColors.bg.primary,
        borderWidth: '1px',
        borderStyle: 'solid',
        borderColor: currentColors.border.default,
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between p-4"
        style={{
          borderBottomWidth: '1px',
          borderBottomStyle: 'solid',
          borderBottomColor: currentColors.border.default,
        }}
      >
        <div className="flex items-center gap-2">
          <MessageCircle size={20} className="text-blue-500" />
          <h3 className="font-semibold" style={{ color: currentColors.text.primary }}>
            Chat com IA
          </h3>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setIsMinimized(!isMinimized)}
            className="transition-colors hover:opacity-70"
            style={{ color: currentColors.text.secondary }}
          >
            {isMinimized ? <Maximize2 size={18} /> : <Minimize2 size={18} />}
          </button>
          <button
            onClick={() => setIsOpen(false)}
            className="transition-colors hover:opacity-70"
            style={{ color: currentColors.text.secondary }}
          >
            <X size={18} />
          </button>
        </div>
      </div>

      {!isMinimized && (
        <>
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.length === 0 && (
              <div
                className="flex flex-col items-center justify-center h-full text-center"
                style={{ color: currentColors.text.secondary }}
              >
                <MessageCircle size={48} className="mb-4 opacity-50" />
                <p className="text-sm">Converse sobre as notícias</p>
                <p className="text-xs mt-2">A IA pode analisar, resumir e responder perguntas</p>
              </div>
            )}

            {messages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className="max-w-[80%] rounded-lg p-3"
                  style={
                    msg.role === 'user'
                      ? {
                          backgroundColor: currentColors.accent.primary,
                          color: currentColors.text.inverse,
                        }
                      : {
                          backgroundColor: currentColors.bg.secondary,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: currentColors.border.default,
                          color: currentColors.text.primary,
                        }
                  }
                >
                  {msg.role === 'assistant' ? (
                    <div className="prose prose-sm max-w-none dark:prose-invert">
                      <ReactMarkdown>{msg.content}</ReactMarkdown>
                    </div>
                  ) : (
                    <p className="whitespace-pre-wrap text-sm">{msg.content}</p>
                  )}
                </div>
              </div>
            ))}

            {isLoading && (
              <div className="flex justify-start">
                <div
                  className="rounded-lg p-3"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderWidth: '1px',
                    borderStyle: 'solid',
                    borderColor: currentColors.border.default,
                  }}
                >
                  <div className="flex gap-1">
                    <div
                      className="w-2 h-2 rounded-full animate-bounce"
                      style={{ backgroundColor: currentColors.text.secondary, animationDelay: '0ms' }}
                    ></div>
                    <div
                      className="w-2 h-2 rounded-full animate-bounce"
                      style={{ backgroundColor: currentColors.text.secondary, animationDelay: '150ms' }}
                    ></div>
                    <div
                      className="w-2 h-2 rounded-full animate-bounce"
                      style={{ backgroundColor: currentColors.text.secondary, animationDelay: '300ms' }}
                    ></div>
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div
            className="p-4"
            style={{
              borderTopWidth: '1px',
              borderTopStyle: 'solid',
              borderTopColor: currentColors.border.default,
            }}
          >
            <div className="flex gap-2">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Pergunte sobre as notícias..."
                disabled={isLoading}
                className="flex-1 px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
              />
              <button
                onClick={handleSend}
                disabled={!inputValue.trim() || isLoading}
                className="bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-4 py-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Send size={18} />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default FloatingChat;
