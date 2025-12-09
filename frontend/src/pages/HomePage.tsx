/**
 * HomePage - Dynamic home page based on user role
 *
 * - Admin: System metrics and administrative actions
 * - Power User: Message history and saved dashboards
 * - Reader: Available dashboards list
 */

import React from 'react';
import { useAuthStore } from '@stores/authStore';
import { useSettingsStore } from '@stores/settingsStore';
import { AdminHome } from '@components/AdminHome';
import { PowerUserHome } from '@components/PowerUserHome';
import { ReaderHome } from '@components/ReaderHome';

export const HomePage: React.FC = () => {
  const { user } = useAuthStore();
  const { currentColors } = useSettingsStore();

  if (!user) {
    return (
      <div className="h-full w-full flex items-center justify-center" style={{
        backgroundColor: currentColors.bg.secondary
      }}>
        <div className="text-center" style={{ color: currentColors.text.muted }}>
          <p>Carregando...</p>
        </div>
      </div>
    );
  }

  // Renderizar componente baseado na role
  const renderRoleBasedHome = () => {
    switch (user.role) {
      case 'admin':
        return <AdminHome />;
      case 'power':
      case 'operator':
        return <PowerUserHome />;
      case 'reader':
      default:
        return <ReaderHome />;
    }
  };

  return (
    <div className="h-full w-full overflow-y-auto overflow-x-hidden" style={{
      background: `linear-gradient(to bottom right, ${currentColors.bg.secondary}, ${currentColors.bg.tertiary})`,
    }}>
      {renderRoleBasedHome()}
    </div>
  );
};
