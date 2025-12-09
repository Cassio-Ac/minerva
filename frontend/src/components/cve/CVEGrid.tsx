import React, { useState } from 'react';
import { Clock, AlertTriangle, X, Shield } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';

interface CVEEntry {
  id: number;
  date: string;
  cve_id: string;
  cve_title: string;
  cve_content: string;
  cve_severity_level: string;
  cve_severity_score: string | number; // Can be string from ES or number
}

interface CVEGridProps {
  cves: CVEEntry[];
}

const CVEGrid: React.FC<CVEGridProps> = ({ cves }) => {
  const { currentColors } = useSettingsStore();
  const [selectedCVE, setSelectedCVE] = useState<CVEEntry | null>(null);

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

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      'CRITICAL': 'bg-red-600 text-white',
      'HIGH': 'bg-orange-600 text-white',
      'MEDIUM': 'bg-yellow-600 text-white',
      'LOW': 'bg-blue-600 text-white',
    };
    return colors[severity.toUpperCase()] || 'bg-gray-600 text-white';
  };

  const getSeverityBadge = (severity: string, score: string | number) => {
    // Convert score to number if it's a string
    const numScore = typeof score === 'string' ? parseFloat(score) : score;
    const displayScore = isNaN(numScore) ? score : numScore.toFixed(1);

    return (
      <div className="flex items-center gap-2">
        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(severity)}`}>
          {severity.toUpperCase()}
        </span>
        <span className="text-xs font-semibold" style={{ color: currentColors.text.primary }}>
          {displayScore}
        </span>
      </div>
    );
  };

  if (cves.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-12"
        style={{ color: currentColors.text.secondary }}
      >
        <AlertTriangle size={48} className="mb-4 opacity-50" />
        <p className="text-lg">Nenhuma CVE encontrada</p>
        <p className="text-sm mt-2">Tente ajustar os filtros</p>
      </div>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {cves.map((cve) => (
          <div
            key={cve.id}
            className="rounded-lg shadow-md p-4 cursor-pointer hover:shadow-lg transition-shadow"
            style={{ backgroundColor: currentColors.bg.primary }}
            onClick={() => setSelectedCVE(cve)}
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              {getSeverityBadge(cve.cve_severity_level, cve.cve_severity_score)}
              <span
                className="text-xs flex items-center"
                style={{ color: currentColors.text.secondary }}
              >
                <Clock size={12} className="mr-1" />
                {formatDate(cve.date)}
              </span>
            </div>

            {/* CVE ID */}
            <div className="mb-2">
              <div className="flex items-center gap-2">
                <Shield size={14} style={{ color: '#3b82f6' }} />
                <span
                  className="text-sm font-semibold"
                  style={{ color: '#3b82f6' }}
                >
                  {cve.cve_id}
                </span>
              </div>
            </div>

            {/* Title */}
            {cve.cve_title && (
              <h4
                className="text-sm font-medium mb-2 line-clamp-2"
                style={{ color: currentColors.text.primary }}
              >
                {cve.cve_title}
              </h4>
            )}

            {/* Content */}
            <p
              className="text-sm mb-3 line-clamp-3"
              style={{ color: currentColors.text.secondary }}
            >
              {cve.cve_content}
            </p>
          </div>
        ))}
      </div>

      {/* Modal */}
      {selectedCVE && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedCVE(null)}
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
                    <Shield size={18} style={{ color: '#3b82f6' }} />
                    <span className="text-lg font-semibold" style={{ color: '#3b82f6' }}>
                      {selectedCVE.cve_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mb-2">
                    {getSeverityBadge(selectedCVE.cve_severity_level, selectedCVE.cve_severity_score)}
                    <span className="text-sm" style={{ color: currentColors.text.secondary }}>
                      {new Date(selectedCVE.date).toLocaleString('pt-BR')}
                    </span>
                  </div>
                  {selectedCVE.cve_title && (
                    <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                      {selectedCVE.cve_title}
                    </h3>
                  )}
                </div>
                <button
                  onClick={() => setSelectedCVE(null)}
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
                    Descrição
                  </h4>
                  <p className="text-sm leading-relaxed" style={{ color: currentColors.text.primary }}>
                    {selectedCVE.cve_content}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                      Severidade
                    </h4>
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(selectedCVE.cve_severity_level, selectedCVE.cve_severity_score)}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                      Data de Publicação
                    </h4>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>
                      {new Date(selectedCVE.date).toLocaleDateString('pt-BR', {
                        day: '2-digit',
                        month: 'long',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                      })}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default CVEGrid;
