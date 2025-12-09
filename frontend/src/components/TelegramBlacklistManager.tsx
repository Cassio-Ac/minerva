/**
 * TelegramBlacklistManager - Manage blacklist filters for Telegram messages
 */

import React, { useState, useEffect } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';

interface BlacklistEntry {
  id: string;
  pattern: string;
  description?: string;
  is_regex: boolean;
  case_sensitive: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface BlacklistManagerProps {
  onClose: () => void;
}

const TelegramBlacklistManager: React.FC<BlacklistManagerProps> = ({ onClose }) => {
  const { currentColors } = useSettingsStore();

  const [entries, setEntries] = useState<BlacklistEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    pattern: '',
    description: '',
    is_regex: false,
    case_sensitive: false,
    is_active: true,
  });

  const [editingId, setEditingId] = useState<string | null>(null);

  // Load blacklist entries
  const loadEntries = async () => {
    setLoading(true);
    try {
      const response = await api.get('/telegram/blacklist?include_inactive=true');
      setEntries(response.data.items || []);
    } catch (error) {
      console.error('Error loading blacklist:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEntries();
  }, []);

  // Handle form submit
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.pattern.trim()) {
      alert('Pattern cannot be empty');
      return;
    }

    setLoading(true);
    try {
      if (editingId) {
        // Update existing entry
        await api.put(`/telegram/blacklist/${editingId}`, formData);
      } else {
        // Create new entry
        await api.post('/telegram/blacklist', formData);
      }

      // Reset form and reload
      setFormData({
        pattern: '',
        description: '',
        is_regex: false,
        case_sensitive: false,
        is_active: true,
      });
      setEditingId(null);
      setShowForm(false);
      await loadEntries();
    } catch (error: any) {
      console.error('Error saving blacklist entry:', error);
      console.error('Error response:', error.response?.data);
      const errorMsg = error.response?.data?.detail || error.message || 'Error saving entry. Please try again.';
      alert(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  // Handle edit
  const handleEdit = (entry: BlacklistEntry) => {
    setFormData({
      pattern: entry.pattern,
      description: entry.description || '',
      is_regex: entry.is_regex,
      case_sensitive: entry.case_sensitive,
      is_active: entry.is_active,
    });
    setEditingId(entry.id);
    setShowForm(true);
  };

  // Handle delete
  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this entry?')) return;

    setLoading(true);
    try {
      await api.delete(`/telegram/blacklist/${id}`);
      await loadEntries();
    } catch (error) {
      console.error('Error deleting entry:', error);
      alert('Error deleting entry. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Handle toggle active
  const handleToggle = async (id: string) => {
    setLoading(true);
    try {
      await api.post(`/telegram/blacklist/${id}/toggle`);
      await loadEntries();
    } catch (error) {
      console.error('Error toggling entry:', error);
      alert('Error toggling entry. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Cancel form
  const handleCancel = () => {
    setFormData({
      pattern: '',
      description: '',
      is_regex: false,
      case_sensitive: false,
      is_active: true,
    });
    setEditingId(null);
    setShowForm(false);
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0,0,0,0.7)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: currentColors.bg.primary,
          borderRadius: '8px',
          padding: '24px',
          maxWidth: '900px',
          width: '100%',
          maxHeight: '90vh',
          overflow: 'auto',
          boxShadow: '0 10px 40px rgba(0,0,0,0.3)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h2 style={{ color: currentColors.text.primary, margin: 0, fontSize: '24px' }}>
            Message Blacklist Manager
          </h2>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: currentColors.text.primary,
              fontSize: '24px',
              cursor: 'pointer',
              padding: '0',
              width: '32px',
              height: '32px',
            }}
          >
            ×
          </button>
        </div>

        <p style={{ color: currentColors.text.secondary, marginBottom: '20px' }}>
          Add patterns to filter out repetitive or unwanted messages from search results
        </p>

        {/* Add New Button */}
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            disabled={loading}
            style={{
              backgroundColor: currentColors.accent.primary,
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              padding: '10px 20px',
              cursor: loading ? 'not-allowed' : 'pointer',
              marginBottom: '20px',
              fontWeight: 500,
            }}
          >
            + Add New Filter
          </button>
        )}

        {/* Form */}
        {showForm && (
          <form onSubmit={handleSubmit} style={{ marginBottom: '24px' }}>
            <div
              style={{
                backgroundColor: currentColors.bg.secondary,
                border: `1px solid ${currentColors.border.default}`,
                borderRadius: '6px',
                padding: '16px',
              }}
            >
              <h3 style={{ color: currentColors.text.primary, marginTop: 0, marginBottom: '16px' }}>
                {editingId ? 'Edit Filter' : 'New Filter'}
              </h3>

              {/* Pattern */}
              <div style={{ marginBottom: '12px' }}>
                <label style={{ color: currentColors.text.primary, display: 'block', marginBottom: '6px', fontWeight: 500 }}>
                  Pattern *
                </label>
                <input
                  type="text"
                  value={formData.pattern}
                  onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
                  placeholder="Text or regex pattern to filter"
                  required
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: currentColors.bg.tertiary,
                    border: `1px solid ${currentColors.border.default}`,
                    borderRadius: '4px',
                    color: currentColors.text.primary,
                    fontSize: '14px',
                  }}
                />
              </div>

              {/* Description */}
              <div style={{ marginBottom: '12px' }}>
                <label style={{ color: currentColors.text.primary, display: 'block', marginBottom: '6px', fontWeight: 500 }}>
                  Description (optional)
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Why is this pattern being filtered?"
                  rows={2}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: currentColors.bg.tertiary,
                    border: `1px solid ${currentColors.border.default}`,
                    borderRadius: '4px',
                    color: currentColors.text.primary,
                    fontSize: '14px',
                    fontFamily: 'inherit',
                    resize: 'vertical',
                  }}
                />
              </div>

              {/* Checkboxes */}
              <div style={{ display: 'flex', gap: '20px', marginBottom: '16px' }}>
                <label style={{ color: currentColors.text.primary, display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={formData.is_regex}
                    onChange={(e) => setFormData({ ...formData, is_regex: e.target.checked })}
                    style={{ marginRight: '6px' }}
                  />
                  Regex Pattern
                </label>

                <label style={{ color: currentColors.text.primary, display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={formData.case_sensitive}
                    onChange={(e) => setFormData({ ...formData, case_sensitive: e.target.checked })}
                    style={{ marginRight: '6px' }}
                  />
                  Case Sensitive
                </label>

                <label style={{ color: currentColors.text.primary, display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={formData.is_active}
                    onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                    style={{ marginRight: '6px' }}
                  />
                  Active
                </label>
              </div>

              {/* Buttons */}
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    backgroundColor: currentColors.accent.primary,
                    color: '#fff',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '8px 16px',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    fontWeight: 500,
                  }}
                >
                  {loading ? 'Saving...' : editingId ? 'Update' : 'Create'}
                </button>
                <button
                  type="button"
                  onClick={handleCancel}
                  disabled={loading}
                  style={{
                    backgroundColor: 'transparent',
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border.default}`,
                    borderRadius: '4px',
                    padding: '8px 16px',
                    cursor: loading ? 'not-allowed' : 'pointer',
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </form>
        )}

        {/* List of entries */}
        <div>
          <h3 style={{ color: currentColors.text.primary, marginBottom: '12px' }}>
            Active Filters ({entries.filter(e => e.is_active).length})
          </h3>

          {loading && entries.length === 0 ? (
            <div style={{ color: currentColors.text.secondary, textAlign: 'center', padding: '20px' }}>
              Loading...
            </div>
          ) : entries.length === 0 ? (
            <div style={{ color: currentColors.text.secondary, textAlign: 'center', padding: '20px' }}>
              No filters yet. Add one to start filtering messages.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {entries.map((entry) => (
                <div
                  key={entry.id}
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    border: `1px solid ${currentColors.border.default}`,
                    borderRadius: '6px',
                    padding: '12px',
                    opacity: entry.is_active ? 1 : 0.5,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                        <code
                          style={{
                            backgroundColor: currentColors.bg.tertiary,
                            padding: '2px 8px',
                            borderRadius: '3px',
                            color: currentColors.accent.primary,
                            fontSize: '13px',
                          }}
                        >
                          {entry.pattern}
                        </code>
                        {entry.is_regex && (
                          <span
                            style={{
                              fontSize: '11px',
                              backgroundColor: '#9333ea',
                              color: '#fff',
                              padding: '2px 6px',
                              borderRadius: '3px',
                            }}
                          >
                            REGEX
                          </span>
                        )}
                        {entry.case_sensitive && (
                          <span
                            style={{
                              fontSize: '11px',
                              backgroundColor: '#ea580c',
                              color: '#fff',
                              padding: '2px 6px',
                              borderRadius: '3px',
                            }}
                          >
                            Aa
                          </span>
                        )}
                        {!entry.is_active && (
                          <span
                            style={{
                              fontSize: '11px',
                              backgroundColor: '#6b7280',
                              color: '#fff',
                              padding: '2px 6px',
                              borderRadius: '3px',
                            }}
                          >
                            INACTIVE
                          </span>
                        )}
                      </div>
                      {entry.description && (
                        <p style={{ color: currentColors.text.secondary, fontSize: '13px', margin: '4px 0 0 0' }}>
                          {entry.description}
                        </p>
                      )}
                    </div>

                    <div style={{ display: 'flex', gap: '8px', marginLeft: '12px' }}>
                      <button
                        onClick={() => handleToggle(entry.id)}
                        disabled={loading}
                        title={entry.is_active ? 'Deactivate' : 'Activate'}
                        style={{
                          backgroundColor: 'transparent',
                          border: `1px solid ${currentColors.border.default}`,
                          borderRadius: '4px',
                          padding: '4px 8px',
                          cursor: loading ? 'not-allowed' : 'pointer',
                          color: currentColors.text.primary,
                          fontSize: '12px',
                        }}
                      >
                        {entry.is_active ? '⏸' : '▶'}
                      </button>
                      <button
                        onClick={() => handleEdit(entry)}
                        disabled={loading}
                        title="Edit"
                        style={{
                          backgroundColor: 'transparent',
                          border: `1px solid ${currentColors.border.default}`,
                          borderRadius: '4px',
                          padding: '4px 8px',
                          cursor: loading ? 'not-allowed' : 'pointer',
                          color: currentColors.text.primary,
                          fontSize: '12px',
                        }}
                      >
                        ✏️
                      </button>
                      <button
                        onClick={() => handleDelete(entry.id)}
                        disabled={loading}
                        title="Delete"
                        style={{
                          backgroundColor: 'transparent',
                          border: `1px solid ${currentColors.border.default}`,
                          borderRadius: '4px',
                          padding: '4px 8px',
                          cursor: loading ? 'not-allowed' : 'pointer',
                          color: '#ef4444',
                          fontSize: '12px',
                        }}
                      >
                        🗑️
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TelegramBlacklistManager;
