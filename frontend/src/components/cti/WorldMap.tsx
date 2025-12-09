/**
 * WorldMap Component - Interactive world map for threat actor visualization
 *
 * Features:
 * - Displays threat actors by country of origin using real geographic data
 * - Click on country to see list of actors
 * - Highlight country when searching for an actor
 * - Theme-aware color scheme
 * - Uses react-simple-maps for accurate country boundaries
 */

import React, { useState, useEffect, useMemo, memo } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
  Marker,
} from 'react-simple-maps';
import { Globe, Users, X, ChevronRight, Loader2, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import { ctiService, CountryActors } from '../../services/cti/ctiService';

// World TopoJSON from Natural Earth
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// ISO 3166-1 alpha-2 to country name mapping
const COUNTRY_NAMES: Record<string, string> = {
  'CN': 'China',
  'RU': 'Russia',
  'US': 'United States',
  'IR': 'Iran',
  'KP': 'North Korea',
  'PK': 'Pakistan',
  'IN': 'India',
  'IL': 'Israel',
  'UA': 'Ukraine',
  'VN': 'Vietnam',
  'LB': 'Lebanon',
  'SY': 'Syria',
  'TR': 'Turkey',
  'EG': 'Egypt',
  'SA': 'Saudi Arabia',
  'AE': 'UAE',
  'KR': 'South Korea',
  'JP': 'Japan',
  'TW': 'Taiwan',
  'GB': 'United Kingdom',
  'DE': 'Germany',
  'FR': 'France',
  'NL': 'Netherlands',
  'BE': 'Belgium',
  'PL': 'Poland',
  'CZ': 'Czech Republic',
  'RO': 'Romania',
  'BG': 'Bulgaria',
  'RS': 'Serbia',
  'BY': 'Belarus',
  'KZ': 'Kazakhstan',
  'UZ': 'Uzbekistan',
  'BR': 'Brazil',
  'MX': 'Mexico',
  'AR': 'Argentina',
  'CO': 'Colombia',
  'VE': 'Venezuela',
  'NG': 'Nigeria',
  'ZA': 'South Africa',
  'KE': 'Kenya',
  'ET': 'Ethiopia',
  'MA': 'Morocco',
  'DZ': 'Algeria',
  'TN': 'Tunisia',
  'LY': 'Libya',
  'SD': 'Sudan',
  'PS': 'Palestine',
  'IQ': 'Iraq',
  'AF': 'Afghanistan',
  'MM': 'Myanmar',
  'TH': 'Thailand',
  'MY': 'Malaysia',
  'SG': 'Singapore',
  'ID': 'Indonesia',
  'PH': 'Philippines',
  'AU': 'Australia',
  'NZ': 'New Zealand',
  'CA': 'Canada',
  'ES': 'Spain',
  'IT': 'Italy',
  'AT': 'Austria',
};

// ISO numeric to ISO alpha-2 mapping (world-atlas uses numeric codes)
const ISO_NUMERIC_TO_ALPHA2: Record<string, string> = {
  '156': 'CN', // China
  '643': 'RU', // Russia
  '840': 'US', // United States
  '364': 'IR', // Iran
  '408': 'KP', // North Korea
  '586': 'PK', // Pakistan
  '356': 'IN', // India
  '376': 'IL', // Israel
  '804': 'UA', // Ukraine
  '704': 'VN', // Vietnam
  '422': 'LB', // Lebanon
  '760': 'SY', // Syria
  '792': 'TR', // Turkey
  '818': 'EG', // Egypt
  '682': 'SA', // Saudi Arabia
  '784': 'AE', // UAE
  '410': 'KR', // South Korea
  '392': 'JP', // Japan
  '158': 'TW', // Taiwan
  '826': 'GB', // United Kingdom
  '276': 'DE', // Germany
  '250': 'FR', // France
  '528': 'NL', // Netherlands
  '056': 'BE', // Belgium
  '616': 'PL', // Poland
  '203': 'CZ', // Czech Republic
  '642': 'RO', // Romania
  '100': 'BG', // Bulgaria
  '688': 'RS', // Serbia
  '112': 'BY', // Belarus
  '398': 'KZ', // Kazakhstan
  '860': 'UZ', // Uzbekistan
  '076': 'BR', // Brazil
  '484': 'MX', // Mexico
  '032': 'AR', // Argentina
  '170': 'CO', // Colombia
  '862': 'VE', // Venezuela
  '566': 'NG', // Nigeria
  '710': 'ZA', // South Africa
  '404': 'KE', // Kenya
  '231': 'ET', // Ethiopia
  '504': 'MA', // Morocco
  '012': 'DZ', // Algeria
  '788': 'TN', // Tunisia
  '434': 'LY', // Libya
  '729': 'SD', // Sudan
  '275': 'PS', // Palestine
  '368': 'IQ', // Iraq
  '004': 'AF', // Afghanistan
  '104': 'MM', // Myanmar
  '764': 'TH', // Thailand
  '458': 'MY', // Malaysia
  '702': 'SG', // Singapore
  '360': 'ID', // Indonesia
  '608': 'PH', // Philippines
  '036': 'AU', // Australia
  '554': 'NZ', // New Zealand
  '124': 'CA', // Canada
  '724': 'ES', // Spain
  '380': 'IT', // Italy
  '040': 'AT', // Austria
};

// Country center coordinates for markers [longitude, latitude]
const COUNTRY_COORDS: Record<string, [number, number]> = {
  'CN': [104, 35],
  'RU': [100, 60],
  'US': [-95, 38],
  'IR': [53, 32],
  'KP': [127, 40],
  'PK': [69, 30],
  'IN': [79, 22],
  'IL': [35, 31],
  'UA': [32, 49],
  'VN': [108, 16],
  'LB': [36, 34],
  'SY': [38, 35],
  'TR': [35, 39],
  'EG': [30, 27],
  'SA': [45, 24],
  'AE': [54, 24],
  'KR': [128, 36],
  'JP': [138, 36],
  'TW': [121, 24],
  'GB': [-3, 54],
  'DE': [10, 51],
  'FR': [2, 47],
  'NL': [5, 52],
  'BE': [4, 51],
  'PL': [19, 52],
  'CZ': [15, 50],
  'RO': [25, 46],
  'BG': [25, 43],
  'RS': [21, 44],
  'BY': [28, 53],
  'KZ': [67, 48],
  'UZ': [64, 41],
  'BR': [-52, -10],
  'MX': [-102, 24],
  'AR': [-64, -34],
  'CO': [-72, 4],
  'VE': [-66, 7],
  'NG': [8, 10],
  'ZA': [25, -29],
  'KE': [38, 1],
  'ET': [40, 9],
  'MA': [-6, 32],
  'DZ': [3, 28],
  'TN': [9, 34],
  'LY': [17, 27],
  'SD': [30, 15],
  'PS': [35, 32],
  'IQ': [44, 33],
  'AF': [67, 34],
  'MM': [96, 22],
  'TH': [101, 15],
  'MY': [102, 4],
  'SG': [104, 1],
  'ID': [117, -2],
  'PH': [122, 12],
  'AU': [134, -25],
  'NZ': [174, -41],
  'CA': [-106, 56],
  'ES': [-4, 40],
  'IT': [12, 43],
  'AT': [14, 47],
};

// Heat map color scale - from cool (low) to hot (high)
// Yellow -> Orange -> Red -> Dark Red
const HEATMAP_COLORS = [
  { threshold: 0, color: '#FEF3C7' },    // Very light yellow (1-2 actors)
  { threshold: 0.15, color: '#FCD34D' }, // Yellow (low)
  { threshold: 0.3, color: '#F59E0B' },  // Orange (medium-low)
  { threshold: 0.5, color: '#EF4444' },  // Red (medium)
  { threshold: 0.7, color: '#DC2626' },  // Dark red (medium-high)
  { threshold: 0.85, color: '#991B1B' }, // Darker red (high)
  { threshold: 1, color: '#7F1D1D' },    // Darkest red (max)
];

// Interpolate between two hex colors
const interpolateColor = (color1: string, color2: string, factor: number): string => {
  const hex = (c: string) => parseInt(c, 16);
  const r1 = hex(color1.slice(1, 3));
  const g1 = hex(color1.slice(3, 5));
  const b1 = hex(color1.slice(5, 7));
  const r2 = hex(color2.slice(1, 3));
  const g2 = hex(color2.slice(3, 5));
  const b2 = hex(color2.slice(5, 7));

  const r = Math.round(r1 + (r2 - r1) * factor);
  const g = Math.round(g1 + (g2 - g1) * factor);
  const b = Math.round(b1 + (b2 - b1) * factor);

  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
};

// Get heat map color based on normalized value (0-1)
const getHeatmapColor = (normalizedValue: number): string => {
  if (normalizedValue <= 0) return HEATMAP_COLORS[0].color;
  if (normalizedValue >= 1) return HEATMAP_COLORS[HEATMAP_COLORS.length - 1].color;

  for (let i = 1; i < HEATMAP_COLORS.length; i++) {
    if (normalizedValue <= HEATMAP_COLORS[i].threshold) {
      const prev = HEATMAP_COLORS[i - 1];
      const curr = HEATMAP_COLORS[i];
      const factor = (normalizedValue - prev.threshold) / (curr.threshold - prev.threshold);
      return interpolateColor(prev.color, curr.color, factor);
    }
  }

  return HEATMAP_COLORS[HEATMAP_COLORS.length - 1].color;
};

interface WorldMapProps {
  onActorClick?: (actorName: string) => void;
  highlightedActor?: string | null;
  className?: string;
}

const WorldMap: React.FC<WorldMapProps> = ({ onActorClick, highlightedActor, className = '' }) => {
  const { currentColors } = useSettingsStore();
  const [countryData, setCountryData] = useState<CountryActors[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCountry, setSelectedCountry] = useState<CountryActors | null>(null);
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const [position, setPosition] = useState({ coordinates: [20, 20] as [number, number], zoom: 1 });

  // Build country code to data mapping
  const countryDataMap = useMemo(() => {
    const map: Record<string, CountryActors> = {};
    countryData.forEach(c => {
      map[c.country] = c;
    });
    return map;
  }, [countryData]);

  // Calculate max count for normalization
  const maxActorCount = useMemo(() => {
    return Math.max(...countryData.map(c => c.count), 1);
  }, [countryData]);

  // Load data on mount
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await ctiService.actors.getActorsByCountry();
      setCountryData(response.countries);
    } catch (err: any) {
      console.error('Error loading actors by country:', err);
      setError(err.response?.data?.detail || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  // Find which country the highlighted actor belongs to
  const highlightedCountry = useMemo(() => {
    if (!highlightedActor) return null;
    const country = countryData.find(c =>
      c.actors.some(a => a.toLowerCase().includes(highlightedActor.toLowerCase()))
    );
    return country?.country || null;
  }, [highlightedActor, countryData]);

  const getMarkerSize = (count: number) => {
    const maxCount = Math.max(...countryData.map(c => c.count), 1);
    const minSize = 4;
    const maxSize = 18;
    return minSize + (count / maxCount) * (maxSize - minSize);
  };

  const handleZoomIn = () => {
    if (position.zoom >= 4) return;
    setPosition(pos => ({ ...pos, zoom: pos.zoom * 1.5 }));
  };

  const handleZoomOut = () => {
    if (position.zoom <= 1) return;
    setPosition(pos => ({ ...pos, zoom: pos.zoom / 1.5 }));
  };

  const handleReset = () => {
    setPosition({ coordinates: [20, 20], zoom: 1 });
  };

  const handleMoveEnd = (pos: { coordinates: [number, number]; zoom: number }) => {
    setPosition(pos);
  };

  // Get country fill color based on state and heat map
  const getCountryFill = (geoId: string) => {
    const countryCode = ISO_NUMERIC_TO_ALPHA2[geoId];
    const countryInfo = countryCode ? countryDataMap[countryCode] : null;
    const isHighlighted = countryCode === highlightedCountry;
    const isSelected = countryCode === selectedCountry?.country;
    const isHovered = countryCode === hoveredCountry;

    // Special states override heat map
    if (isHighlighted) {
      return '#3B82F6'; // Blue for search highlight (stands out from heat colors)
    }
    if (isSelected) {
      return currentColors.accent.primary;
    }
    if (isHovered && countryInfo) {
      // Slightly brighter version for hover
      const normalizedCount = countryInfo.count / maxActorCount;
      const baseColor = getHeatmapColor(normalizedCount);
      return baseColor;
    }

    // Heat map color based on actor count
    if (countryInfo) {
      const normalizedCount = countryInfo.count / maxActorCount;
      return getHeatmapColor(normalizedCount);
    }

    // No actors - neutral color
    return currentColors.bg.tertiary;
  };

  // Get marker color that contrasts with heat map
  const getMarkerColor = (count: number, isHighlighted: boolean, isSelected: boolean) => {
    if (isHighlighted) return '#3B82F6';
    if (isSelected) return currentColors.accent.primary;

    // Use dark color for markers to contrast with heat map
    const normalizedCount = count / maxActorCount;
    if (normalizedCount > 0.5) {
      return '#FFFFFF'; // White text on dark red backgrounds
    }
    return '#1F2937'; // Dark text on yellow/orange backgrounds
  };

  if (loading) {
    return (
      <div
        className={`flex items-center justify-center h-96 rounded-lg ${className}`}
        style={{ backgroundColor: currentColors.bg.primary }}
      >
        <Loader2 className="animate-spin" size={32} style={{ color: currentColors.accent.primary }} />
      </div>
    );
  }

  if (error) {
    return (
      <div
        className={`flex flex-col items-center justify-center h-96 rounded-lg ${className}`}
        style={{ backgroundColor: currentColors.bg.primary }}
      >
        <p className="text-sm" style={{ color: currentColors.accent.error }}>{error}</p>
        <button
          onClick={loadData}
          className="mt-2 px-3 py-1 rounded text-sm"
          style={{ backgroundColor: currentColors.accent.primary, color: currentColors.text.inverse }}
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className={`relative h-full flex flex-col ${className}`}>
      {/* Map Container */}
      <div
        className="rounded-lg overflow-hidden flex-1 flex flex-col"
        style={{ backgroundColor: currentColors.bg.secondary }}
      >
        {/* Header */}
        <div
          className="px-4 py-3 border-b flex items-center justify-between"
          style={{ borderColor: currentColors.border.default }}
        >
          <div className="flex items-center gap-2">
            <Globe size={20} style={{ color: currentColors.accent.primary }} />
            <h3 className="font-semibold" style={{ color: currentColors.text.primary }}>
              Threat Actors by Country of Origin
            </h3>
          </div>
          <div className="flex items-center gap-4 text-sm" style={{ color: currentColors.text.secondary }}>
            <span>{countryData.length} countries</span>
            <span>{countryData.reduce((sum, c) => sum + c.count, 0)} actors</span>
          </div>
        </div>

        {/* Map */}
        <div className="relative flex-1" style={{ minHeight: '400px' }}>
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{
              scale: 140,
              center: [20, 20],
            }}
            style={{
              width: '100%',
              height: '100%',
              backgroundColor: currentColors.bg.primary,
            }}
          >
            <ZoomableGroup
              zoom={position.zoom}
              center={position.coordinates}
              onMoveEnd={handleMoveEnd}
              minZoom={1}
              maxZoom={4}
            >
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map(geo => {
                    const geoId = geo.id;
                    const countryCode = ISO_NUMERIC_TO_ALPHA2[geoId];
                    const hasActors = countryCode && countryDataMap[countryCode];

                    return (
                      <Geography
                        key={geo.rsmKey}
                        geography={geo}
                        fill={getCountryFill(geoId)}
                        stroke={currentColors.border.default}
                        strokeWidth={0.5}
                        style={{
                          default: {
                            outline: 'none',
                          },
                          hover: {
                            fill: hasActors
                              ? currentColors.accent.primaryHover
                              : currentColors.bg.tertiary,
                            outline: 'none',
                            cursor: hasActors ? 'pointer' : 'default',
                          },
                          pressed: {
                            fill: currentColors.accent.primary,
                            outline: 'none',
                          },
                        }}
                        onMouseEnter={() => {
                          if (countryCode) setHoveredCountry(countryCode);
                        }}
                        onMouseLeave={() => {
                          setHoveredCountry(null);
                        }}
                        onClick={() => {
                          if (countryCode && countryDataMap[countryCode]) {
                            setSelectedCountry(countryDataMap[countryCode]);
                          }
                        }}
                      />
                    );
                  })
                }
              </Geographies>

              {/* Actor count markers */}
              {countryData.map(country => {
                const coords = COUNTRY_COORDS[country.country];
                if (!coords) return null;

                const size = getMarkerSize(country.count);
                const isHighlighted = highlightedCountry === country.country;
                const isSelected = selectedCountry?.country === country.country;
                const normalizedCount = country.count / maxActorCount;
                const markerTextColor = getMarkerColor(country.count, isHighlighted, isSelected);

                return (
                  <Marker
                    key={country.country}
                    coordinates={coords}
                    onClick={() => setSelectedCountry(country)}
                  >
                    {/* Pulse animation for highlighted */}
                    {isHighlighted && (
                      <circle
                        r={size + 8}
                        fill="none"
                        stroke="#3B82F6"
                        strokeWidth="2"
                        opacity="0.6"
                      >
                        <animate
                          attributeName="r"
                          from={size + 2}
                          to={size + 12}
                          dur="1.5s"
                          repeatCount="indefinite"
                        />
                        <animate
                          attributeName="opacity"
                          from="0.6"
                          to="0"
                          dur="1.5s"
                          repeatCount="indefinite"
                        />
                      </circle>
                    )}

                    {/* Marker circle - semi-transparent dark background for contrast */}
                    <circle
                      r={size}
                      fill={isHighlighted
                        ? '#3B82F6'
                        : isSelected
                          ? currentColors.accent.primary
                          : 'rgba(0, 0, 0, 0.6)'}
                      stroke={isHighlighted
                        ? '#3B82F6'
                        : isSelected
                          ? currentColors.accent.primary
                          : normalizedCount > 0.5 ? '#FFFFFF' : '#1F2937'}
                      strokeWidth={1.5}
                      style={{ cursor: 'pointer' }}
                    />

                    {/* Count text */}
                    {size > 6 && (
                      <text
                        textAnchor="middle"
                        y={4}
                        style={{
                          fontSize: size > 12 ? '10px' : '8px',
                          fontWeight: 'bold',
                          fill: '#FFFFFF',
                          pointerEvents: 'none',
                        }}
                      >
                        {country.count}
                      </text>
                    )}
                  </Marker>
                );
              })}
            </ZoomableGroup>
          </ComposableMap>

          {/* Zoom controls */}
          <div
            className="absolute bottom-4 right-4 flex flex-col gap-1 rounded-lg overflow-hidden shadow-lg"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            <button
              onClick={handleZoomIn}
              className="p-2 hover:bg-opacity-80 transition-colors"
              style={{ borderBottom: `1px solid ${currentColors.border.default}` }}
              title="Zoom in"
            >
              <ZoomIn size={18} style={{ color: currentColors.text.primary }} />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-2 hover:bg-opacity-80 transition-colors"
              style={{ borderBottom: `1px solid ${currentColors.border.default}` }}
              title="Zoom out"
            >
              <ZoomOut size={18} style={{ color: currentColors.text.primary }} />
            </button>
            <button
              onClick={handleReset}
              className="p-2 hover:bg-opacity-80 transition-colors"
              title="Reset view"
            >
              <RotateCcw size={18} style={{ color: currentColors.text.primary }} />
            </button>
          </div>

          {/* Tooltip */}
          {hoveredCountry && !selectedCountry && (
            <div
              className="absolute pointer-events-none px-3 py-2 rounded-lg shadow-lg text-sm z-10"
              style={{
                backgroundColor: currentColors.bg.primary,
                border: `1px solid ${currentColors.border.default}`,
                top: '10px',
                left: '10px',
              }}
            >
              <p className="font-semibold" style={{ color: currentColors.text.primary }}>
                {COUNTRY_NAMES[hoveredCountry] || hoveredCountry}
              </p>
              <p style={{ color: currentColors.text.secondary }}>
                {countryDataMap[hoveredCountry]?.count || 0} threat actors
              </p>
            </div>
          )}
        </div>

        {/* Legend */}
        <div
          className="px-4 py-3 border-t flex items-center gap-6 text-xs"
          style={{ borderColor: currentColors.border.default, color: currentColors.text.secondary }}
        >
          {/* Heat map gradient legend */}
          <div className="flex items-center gap-2">
            <span>Low</span>
            <div
              className="h-3 w-32 rounded"
              style={{
                background: `linear-gradient(to right, ${HEATMAP_COLORS.map(c => c.color).join(', ')})`,
              }}
            />
            <span>High</span>
          </div>

          <span className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: '#3B82F6' }}
            />
            Search match
          </span>
          <span className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: currentColors.accent.primary }}
            />
            Selected
          </span>
          <span className="ml-auto opacity-70">
            Max: {maxActorCount} actors • Click country to view • Scroll to zoom
          </span>
        </div>
      </div>

      {/* Country Details Panel */}
      {selectedCountry && (
        <div
          className="absolute top-0 right-0 w-80 h-full rounded-lg shadow-xl overflow-hidden z-20"
          style={{ backgroundColor: currentColors.bg.primary }}
        >
          {/* Header */}
          <div
            className="px-4 py-3 border-b flex items-center justify-between"
            style={{
              borderColor: currentColors.border.default,
              backgroundColor: currentColors.accent.primary,
            }}
          >
            <div className="flex items-center gap-2">
              <Users size={18} style={{ color: currentColors.text.inverse }} />
              <div>
                <h4 className="font-semibold" style={{ color: currentColors.text.inverse }}>
                  {COUNTRY_NAMES[selectedCountry.country] || selectedCountry.country}
                </h4>
                <p className="text-xs" style={{ color: currentColors.text.inverse, opacity: 0.8 }}>
                  {selectedCountry.count} threat actors
                </p>
              </div>
            </div>
            <button
              onClick={() => setSelectedCountry(null)}
              className="p-1 rounded hover:bg-white/20 transition-colors"
            >
              <X size={18} style={{ color: currentColors.text.inverse }} />
            </button>
          </div>

          {/* Actor List */}
          <div className="overflow-y-auto" style={{ maxHeight: 'calc(100% - 70px)' }}>
            {selectedCountry.actors.map((actor, idx) => {
              const isHighlighted = highlightedActor &&
                actor.toLowerCase().includes(highlightedActor.toLowerCase());

              return (
                <button
                  key={`${actor}-${idx}`}
                  onClick={() => onActorClick?.(actor)}
                  className="w-full px-4 py-2.5 text-left flex items-center justify-between hover:bg-opacity-80 transition-colors"
                  style={{
                    backgroundColor: isHighlighted
                      ? `${currentColors.accent.warning}20`
                      : 'transparent',
                    borderBottom: `1px solid ${currentColors.border.default}`,
                  }}
                >
                  <span
                    className="text-sm truncate font-medium"
                    style={{
                      color: isHighlighted
                        ? currentColors.accent.warning
                        : currentColors.text.primary,
                    }}
                  >
                    {actor}
                  </span>
                  <ChevronRight
                    size={16}
                    style={{ color: currentColors.text.muted, flexShrink: 0 }}
                  />
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default memo(WorldMap);
