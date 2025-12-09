import React, { useState } from 'react';
import { Clock, AlertTriangle, X, Shield, User } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';

interface BreachEntry {
  id: number;
  date: string;
  breach_source: string;
  breach_content: string;
  breach_author: string;
  breach_type: string;
}

interface BreachGridProps {
  breaches: BreachEntry[];
}

const BreachGrid: React.FC<BreachGridProps> = ({ breaches }) => {
  const { currentColors } = useSettingsStore();
  const [selectedBreach, setSelectedBreach] = useState<BreachEntry | null>(null);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m atrás`;
    if (diffHours < 24) return `${diffHours}h atrás`;
    if (diffDays < 7) return `${diffDays}d atrás`;

    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: 'short',
      year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
    });
  };

  const getTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      'ransomware': 'bg-red-600 text-white',
      'Data leak': 'bg-orange-600 text-white',
      'DDoS Attack': 'bg-purple-600 text-white',
    };
    return colors[type] || 'bg-gray-600 text-white';
  };

  if (breaches.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-12"
        style={{ color: currentColors.text.secondary }}
      >
        <AlertTriangle size={48} className="mb-4 opacity-50" />
        <p className="text-lg">Nenhum vazamento encontrado</p>
        <p className="text-sm mt-2">Tente ajustar os filtros</p>
      </div>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {breaches.map((breach) => (
          <div
            key={breach.id}
            className="rounded-lg shadow-md p-4 cursor-pointer hover:shadow-lg transition-shadow"
            style={{ backgroundColor: currentColors.bg.primary }}
            onClick={() => setSelectedBreach(breach)}
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              <span
                className={`px-2 py-1 rounded text-xs font-medium ${getTypeColor(breach.breach_type)}`}
              >
                {breach.breach_type}
              </span>
              <span
                className="text-xs flex items-center"
                style={{ color: currentColors.text.secondary }}
              >
                <Clock size={12} className="mr-1" />
                {formatDate(breach.date)}
              </span>
            </div>

            {/* Content */}
            <p
              className="text-sm mb-3 line-clamp-3"
              style={{ color: currentColors.text.primary }}
            >
              {breach.breach_content}
            </p>

            {/* Footer */}
            <div className="flex items-center justify-between text-xs" style={{ color: currentColors.text.secondary }}>
              <div className="flex items-center">
                <Shield size={12} className="mr-1" />
                <span className="truncate max-w-[150px]">{breach.breach_source}</span>
              </div>
              {breach.breach_author && (
                <div className="flex items-center">
                  <User size={12} className="mr-1" />
                  <span className="truncate max-w-[100px]">{breach.breach_author}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Modal */}
      {selectedBreach && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedBreach(null)}
        >
          <div
            className="rounded-lg shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
            style={{ backgroundColor: currentColors.bg.primary }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="sticky top-0 p-6 border-b" style={{ backgroundColor: currentColors.bg.primary, borderColor: currentColors.border }}>
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getTypeColor(selectedBreach.breach_type)}`}>
                      {selectedBreach.breach_type}
                    </span>
                    <span className="text-sm" style={{ color: currentColors.text.secondary }}>
                      {new Date(selectedBreach.date).toLocaleString('pt-BR')}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedBreach(null)}
                  className="p-1 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                  style={{ color: currentColors.text.secondary }}
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6">
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                    Conteúdo
                  </h4>
                  <p className="text-sm leading-relaxed" style={{ color: currentColors.text.primary }}>
                    {selectedBreach.breach_content}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                      Fonte
                    </h4>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>
                      {selectedBreach.breach_source}
                    </p>
                  </div>
                  {selectedBreach.breach_author && (
                    <div>
                      <h4 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                        Autor
                      </h4>
                      <p className="text-sm" style={{ color: currentColors.text.primary }}>
                        {selectedBreach.breach_author}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default BreachGrid;
