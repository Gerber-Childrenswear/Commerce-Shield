
import { useEffect, useMemo, useRef, useState, type ChangeEventHandler } from 'react';
import './App.css';

type FlairView = 'overview' | 'badges' | 'banners' | 'settings';
type SafeMode = 'strict' | 'balanced' | 'off';

type BadgeCard = {
  id: string;
  label: string;
  conditions: number;
  tone: 'blue' | 'navy' | 'red' | 'orange' | 'green';
  customCssRaw: string;
  safeMode: SafeMode;
};

type BannerCard = {
  id: string;
  title: string;
  subtitle: string;
  conditions: number;
  tags?: number;
  style: 'sky' | 'deep' | 'sage';
  dot: 'green' | 'pink';
  customCssRaw: string;
  safeMode: SafeMode;
};

type EditorState =
  | { open: false }
  | { open: true; kind: 'badge'; index: number; draft: BadgeCard; original: BadgeCard }
  | { open: true; kind: 'banner'; index: number; draft: BannerCard; original: BannerCard };

const badgeCards: BadgeCard[] = [
  { id: '1', label: 'ONLY $5', conditions: 3, tone: 'blue', customCssRaw: '', safeMode: 'balanced' },
  { id: '2', label: 'ONLY $10', conditions: 3, tone: 'blue', customCssRaw: '', safeMode: 'balanced' },
  { id: '3', label: 'ONLY $8', conditions: 3, tone: 'blue', customCssRaw: '', safeMode: 'balanced' },
  { id: '4', label: 'FREE EMBROIDERY', conditions: 2, tone: 'navy', customCssRaw: '', safeMode: 'balanced' },
  { id: '5', label: '2-Way Zipper', conditions: 2, tone: 'blue', customCssRaw: '', safeMode: 'balanced' },
  { id: '6', label: 'PRICE DROP', conditions: 2, tone: 'blue', customCssRaw: '', safeMode: 'balanced' },
  { id: '7', label: 'ONLINE ONLY!', conditions: 2, tone: 'red', customCssRaw: '', safeMode: 'balanced' },
  { id: '8', label: 'ONLY 3 LEFT!', conditions: 3, tone: 'red', customCssRaw: '', safeMode: 'balanced' },
  { id: '9', label: 'ALMOST GONE', conditions: 2, tone: 'orange', customCssRaw: '', safeMode: 'balanced' },
  { id: '10', label: 'NEW', conditions: 3, tone: 'navy', customCssRaw: '', safeMode: 'balanced' },
  { id: '11', label: 'LOOSE FITTING', conditions: 2, tone: 'navy', customCssRaw: '', safeMode: 'balanced' },
  { id: '12', label: 'Our OOPS = Your DEAL!', conditions: 2, tone: 'navy', customCssRaw: '', safeMode: 'balanced' },
];

const bannerCards: BannerCard[] = [
  {
    id: '1',
    title: 'PRICE DROP!!!',
    subtitle: "Everyday essentials at prices you'll love. Limited Time Only.",
    conditions: 2,
    style: 'sky',
    dot: 'green',
    customCssRaw: '',
    safeMode: 'balanced',
  },
  {
    id: '2',
    title: 'FINAL HOURS TO SAVE',
    subtitle: 'From $5 ends TONIGHT! While supplies last',
    conditions: 2,
    style: 'sky',
    dot: 'pink',
    customCssRaw: '',
    safeMode: 'balanced',
  },
  {
    id: '3',
    title: 'Oops for us. Awesome for you!',
    subtitle: "We printed UPSIDE DOWN so now it's priced extra low!",
    conditions: 1,
    style: 'deep',
    dot: 'green',
    customCssRaw: '',
    safeMode: 'balanced',
  },
  {
    id: '4',
    title: 'Create a keepsake as unique as your little one.',
    subtitle: 'Enjoy FREE EMBROIDERY for a limited time.',
    conditions: 2,
    style: 'deep',
    dot: 'green',
    customCssRaw: '',
    safeMode: 'balanced',
  },
  {
    id: '5',
    title: 'BEST PAJAMA SETS EVER',
    subtitle: 'Buttery soft styles designed for comfort.',
    conditions: 3,
    tags: 1,
    style: 'sage',
    dot: 'green',
    customCssRaw: '',
    safeMode: 'balanced',
  },
  {
    id: '6',
    title: 'SNUGGLY-SOFT FOOTED PJS',
    subtitle: 'Featuring new two-way zipper for effortless changes.',
    conditions: 3,
    tags: 1,
    style: 'sage',
    dot: 'green',
    customCssRaw: '',
    safeMode: 'balanced',
  },
];

const appNav = ['Home', 'Orders', 'Products', 'Customers', 'Marketing', 'Discounts', 'Content', 'Markets', 'Finance', 'Analytics'] as const;

const BADGES_STORAGE_KEY = 'gcw.flair.badges.v1';
const BANNERS_STORAGE_KEY = 'gcw.flair.banners.v1';
const FLAIR_EXPORT_VERSION = 1;

type FlairConfigExport = {
  version: number;
  exportedAt: string;
  badges: BadgeCard[];
  banners: BannerCard[];
};

type ImportMode = 'replace' | 'merge';

type ImportSummary = {
  fileName: string;
  mode: ImportMode;
  badgeUpdated: number;
  badgeAdded: number;
  badgeReplaced: number;
  bannerUpdated: number;
  bannerAdded: number;
  bannerReplaced: number;
  skippedBadges: number;
  skippedBanners: number;
};

type GuidanceTone = 'info' | 'success' | 'warning' | 'error';

type GuidanceMessage = {
  tone: GuidanceTone;
  title: string;
  detail: string;
};

type ImportIssue = {
  entity: 'badge' | 'banner';
  index: number;
  reason: string;
};

type ImportFix = {
  entity: 'badge' | 'banner';
  index: number;
  field: string;
  from: string;
  to: string;
};

type ValidationResult<T> = {
  value?: T;
  issue?: ImportIssue;
  fixes: ImportFix[];
};

type PendingImport = {
  fileName: string;
  strict: ParsedImportData;
  assisted: ParsedImportData;
};

type ParsedImportData = {
  badges: BadgeCard[];
  banners: BannerCard[];
  issues: ImportIssue[];
  fixes: ImportFix[];
};

type ImportPreviewStats = {
  badgeUpdated: number;
  badgeAdded: number;
  badgeReplaced: number;
  bannerUpdated: number;
  bannerAdded: number;
  bannerReplaced: number;
};

function createDefaultBadges(): BadgeCard[] {
  return badgeCards.map((card) => ({ ...card }));
}

function createDefaultBanners(): BannerCard[] {
  return bannerCards.map((card) => ({ ...card }));
}

function isEditorDirty(editor: Extract<EditorState, { open: true }>): boolean {
  return JSON.stringify(editor.draft) !== JSON.stringify(editor.original);
}

function getCssWarnings(rawCss: string, safeMode: SafeMode): string[] {
  const warnings: string[] = [];

  if (/\@import\b/i.test(rawCss)) {
    if (safeMode === 'off') {
      warnings.push('Using @import can pull external CSS into the page.');
    } else {
      warnings.push('Safety mode strips @import rules before applying CSS.');
    }
  }

  if (/expression\s*\(/i.test(rawCss)) {
    if (safeMode === 'off') {
      warnings.push('CSS expression() is unsafe and may break rendering.');
    } else {
      warnings.push('Safety mode strips expression() calls.');
    }
  }

  if (/javascript\s*:/i.test(rawCss)) {
    if (safeMode === 'off') {
      warnings.push('javascript: URLs are unsafe in CSS and should be removed.');
    } else {
      warnings.push('Safety mode strips javascript: URLs from CSS.');
    }
  }

  if (safeMode === 'strict' && /position\s*:\s*(fixed|sticky)\b/i.test(rawCss)) {
    warnings.push('Strict mode strips fixed/sticky positioning.');
  }

  if (safeMode === 'strict' && /z-index\s*:/i.test(rawCss)) {
    warnings.push('Strict mode strips z-index values.');
  }

  if (rawCss.includes('{') && !/\.flair-campaign\b/.test(rawCss)) {
    warnings.push('No .flair-campaign selector found. Add it to keep styles campaign-scoped.');
  }

  if (/(^|\W)(html|body|:root)\b/i.test(rawCss)) {
    warnings.push('Global selectors (html/body/:root) can style the full app surface.');
  }

  return warnings;
}

function isBadgeTone(value: string): value is BadgeCard['tone'] {
  return value === 'blue' || value === 'navy' || value === 'red' || value === 'orange' || value === 'green';
}

function isBannerStyle(value: string): value is BannerCard['style'] {
  return value === 'sky' || value === 'deep' || value === 'sage';
}

function isDot(value: string): value is BannerCard['dot'] {
  return value === 'green' || value === 'pink';
}

function isSafeMode(value: string): value is SafeMode {
  return value === 'strict' || value === 'balanced' || value === 'off';
}

function toBadgeCard(input: unknown): BadgeCard | null {
  if (!input || typeof input !== 'object') return null;
  const value = input as Record<string, unknown>;
  if (typeof value.id !== 'string') return null;
  if (typeof value.label !== 'string') return null;
  if (typeof value.conditions !== 'number') return null;
  if (typeof value.tone !== 'string' || !isBadgeTone(value.tone)) return null;
  const customCssRaw = typeof value.customCssRaw === 'string' ? value.customCssRaw : '';
  const safeMode = typeof value.safeMode === 'string' && isSafeMode(value.safeMode) ? value.safeMode : 'balanced';
  return {
    id: value.id,
    label: value.label,
    conditions: value.conditions,
    tone: value.tone,
    customCssRaw,
    safeMode,
  };
}

function toBannerCard(input: unknown): BannerCard | null {
  if (!input || typeof input !== 'object') return null;
  const value = input as Record<string, unknown>;
  if (typeof value.id !== 'string') return null;
  if (typeof value.title !== 'string') return null;
  if (typeof value.subtitle !== 'string') return null;
  if (typeof value.conditions !== 'number') return null;
  if (typeof value.style !== 'string' || !isBannerStyle(value.style)) return null;
  if (typeof value.dot !== 'string' || !isDot(value.dot)) return null;
  const tags = typeof value.tags === 'number' ? value.tags : undefined;
  const customCssRaw = typeof value.customCssRaw === 'string' ? value.customCssRaw : '';
  const safeMode = typeof value.safeMode === 'string' && isSafeMode(value.safeMode) ? value.safeMode : 'balanced';
  return {
    id: value.id,
    title: value.title,
    subtitle: value.subtitle,
    conditions: value.conditions,
    tags,
    style: value.style,
    dot: value.dot,
    customCssRaw,
    safeMode,
  };
}

function loadStoredBadges(): BadgeCard[] {
  if (typeof window === 'undefined') return createDefaultBadges();
  try {
    const raw = window.localStorage.getItem(BADGES_STORAGE_KEY);
    if (!raw) return createDefaultBadges();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return createDefaultBadges();
    const normalized = parsed.map(toBadgeCard).filter((value): value is BadgeCard => value !== null);
    return normalized.length ? normalized : createDefaultBadges();
  } catch {
    return createDefaultBadges();
  }
}

function loadStoredBanners(): BannerCard[] {
  if (typeof window === 'undefined') return createDefaultBanners();
  try {
    const raw = window.localStorage.getItem(BANNERS_STORAGE_KEY);
    if (!raw) return createDefaultBanners();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return createDefaultBanners();
    const normalized = parsed.map(toBannerCard).filter((value): value is BannerCard => value !== null);
    return normalized.length ? normalized : createDefaultBanners();
  } catch {
    return createDefaultBanners();
  }
}

function mergeById<T extends { id: string }>(current: T[], incoming: T[]): { next: T[]; updated: number; added: number } {
  const currentById = new Map(current.map((item) => [item.id, item]));
  let updated = 0;
  let added = 0;

  incoming.forEach((item) => {
    if (currentById.has(item.id)) {
      updated += 1;
    } else {
      added += 1;
    }
    currentById.set(item.id, item);
  });

  const nextInOrder = current.map((item) => currentById.get(item.id) ?? item);
  const appended = incoming.filter((item) => !current.some((existing) => existing.id === item.id));
  return { next: [...nextInOrder, ...appended], updated, added };
}

function normalizeToken(input: string): string {
  return input.trim().toLowerCase().replace(/[_\-\s]+/g, ' ');
}

function normalizeBadgeTone(raw: string): BadgeCard['tone'] | null {
  const token = normalizeToken(raw);
  if (token === 'blue' || token === 'blu' || token === 'light blue') return 'blue';
  if (token === 'navy' || token === 'dark blue' || token === 'navy blue') return 'navy';
  if (token === 'red') return 'red';
  if (token === 'orange') return 'orange';
  if (token === 'green' || token === 'sage') return 'green';
  return null;
}

function normalizeBannerStyle(raw: string): BannerCard['style'] | null {
  const token = normalizeToken(raw);
  if (token === 'sky' || token === 'light blue') return 'sky';
  if (token === 'deep' || token === 'navy' || token === 'dark') return 'deep';
  if (token === 'sage' || token === 'green') return 'sage';
  return null;
}

function normalizeDot(raw: string): BannerCard['dot'] | null {
  const token = normalizeToken(raw);
  if (token === 'green' || token === 'green dot') return 'green';
  if (token === 'pink' || token === 'pink dot') return 'pink';
  return null;
}

function normalizeSafeMode(raw: string): SafeMode | null {
  const token = normalizeToken(raw);
  if (token === 'strict') return 'strict';
  if (token === 'balanced' || token === 'default') return 'balanced';
  if (token === 'off' || token === 'none' || token === 'disabled') return 'off';
  return null;
}

function normalizeNumber(raw: unknown): number | null {
  if (typeof raw === 'number' && !Number.isNaN(raw)) return raw;
  if (typeof raw === 'string') {
    const parsed = Number(raw.trim());
    if (!Number.isNaN(parsed)) return parsed;
  }
  return null;
}

function validateBadgeEntry(input: unknown, index: number, assisted: boolean): ValidationResult<BadgeCard> {
  const fixes: ImportFix[] = [];

  if (!input || typeof input !== 'object') {
    return { issue: { entity: 'badge', index, reason: 'Entry is not an object.' }, fixes };
  }

  const value = input as Record<string, unknown>;

  const id = typeof value.id === 'string' ? value.id.trim() : '';
  if (!id) {
    return { issue: { entity: 'badge', index, reason: 'Missing or invalid id.' }, fixes };
  }

  const label = typeof value.label === 'string' ? value.label.trim() : '';
  if (!label) {
    return { issue: { entity: 'badge', index, reason: 'Missing or invalid label.' }, fixes };
  }

  const normalizedConditions = assisted ? normalizeNumber(value.conditions) : (typeof value.conditions === 'number' && !Number.isNaN(value.conditions) ? value.conditions : null);
  if (normalizedConditions === null) {
    return { issue: { entity: 'badge', index, reason: 'conditions must be a number.' }, fixes };
  }
  if (assisted && typeof value.conditions === 'string') {
    fixes.push({ entity: 'badge', index, field: 'conditions', from: value.conditions, to: String(normalizedConditions) });
  }

  if (typeof value.tone !== 'string') {
    return { issue: { entity: 'badge', index, reason: 'tone must be one of blue/navy/red/orange/green.' }, fixes };
  }
  const normalizedTone = assisted ? normalizeBadgeTone(value.tone) : (isBadgeTone(value.tone) ? value.tone : null);
  if (!normalizedTone) {
    return { issue: { entity: 'badge', index, reason: 'tone must be one of blue/navy/red/orange/green.' }, fixes };
  }
  if (assisted && value.tone !== normalizedTone) {
    fixes.push({ entity: 'badge', index, field: 'tone', from: value.tone, to: normalizedTone });
  }

  const customCssRaw = typeof value.customCssRaw === 'string' ? value.customCssRaw : '';
  let safeMode: SafeMode = 'balanced';
  if (typeof value.safeMode === 'string') {
    const normalizedSafeMode = assisted ? normalizeSafeMode(value.safeMode) : (isSafeMode(value.safeMode) ? value.safeMode : null);
    if (normalizedSafeMode) {
      safeMode = normalizedSafeMode;
      if (assisted && value.safeMode !== normalizedSafeMode) {
        fixes.push({ entity: 'badge', index, field: 'safeMode', from: value.safeMode, to: normalizedSafeMode });
      }
    }
  }

  return {
    value: {
      id,
      label,
      conditions: normalizedConditions,
      tone: normalizedTone,
      customCssRaw,
      safeMode,
    },
    fixes,
  };
}

function validateBannerEntry(input: unknown, index: number, assisted: boolean): ValidationResult<BannerCard> {
  const fixes: ImportFix[] = [];

  if (!input || typeof input !== 'object') {
    return { issue: { entity: 'banner', index, reason: 'Entry is not an object.' }, fixes };
  }

  const value = input as Record<string, unknown>;

  const id = typeof value.id === 'string' ? value.id.trim() : '';
  if (!id) {
    return { issue: { entity: 'banner', index, reason: 'Missing or invalid id.' }, fixes };
  }

  const title = typeof value.title === 'string' ? value.title.trim() : '';
  if (!title) {
    return { issue: { entity: 'banner', index, reason: 'Missing or invalid title.' }, fixes };
  }

  const subtitle = typeof value.subtitle === 'string' ? value.subtitle : '';
  if (!subtitle) {
    return { issue: { entity: 'banner', index, reason: 'Missing or invalid subtitle.' }, fixes };
  }

  const normalizedConditions = assisted ? normalizeNumber(value.conditions) : (typeof value.conditions === 'number' && !Number.isNaN(value.conditions) ? value.conditions : null);
  if (normalizedConditions === null) {
    return { issue: { entity: 'banner', index, reason: 'conditions must be a number.' }, fixes };
  }
  if (assisted && typeof value.conditions === 'string') {
    fixes.push({ entity: 'banner', index, field: 'conditions', from: value.conditions, to: String(normalizedConditions) });
  }

  if (typeof value.style !== 'string') {
    return { issue: { entity: 'banner', index, reason: 'style must be one of sky/deep/sage.' }, fixes };
  }
  const normalizedStyle = assisted ? normalizeBannerStyle(value.style) : (isBannerStyle(value.style) ? value.style : null);
  if (!normalizedStyle) {
    return { issue: { entity: 'banner', index, reason: 'style must be one of sky/deep/sage.' }, fixes };
  }
  if (assisted && value.style !== normalizedStyle) {
    fixes.push({ entity: 'banner', index, field: 'style', from: value.style, to: normalizedStyle });
  }

  if (typeof value.dot !== 'string') {
    return { issue: { entity: 'banner', index, reason: 'dot must be green or pink.' }, fixes };
  }
  const normalizedDot = assisted ? normalizeDot(value.dot) : (isDot(value.dot) ? value.dot : null);
  if (!normalizedDot) {
    return { issue: { entity: 'banner', index, reason: 'dot must be green or pink.' }, fixes };
  }
  if (assisted && value.dot !== normalizedDot) {
    fixes.push({ entity: 'banner', index, field: 'dot', from: value.dot, to: normalizedDot });
  }

  let tags: number | undefined;
  if (typeof value.tags !== 'undefined') {
    const normalizedTags = assisted ? normalizeNumber(value.tags) : (typeof value.tags === 'number' && !Number.isNaN(value.tags) ? value.tags : null);
    if (normalizedTags !== null) {
      tags = normalizedTags;
      if (assisted && typeof value.tags === 'string') {
        fixes.push({ entity: 'banner', index, field: 'tags', from: value.tags, to: String(normalizedTags) });
      }
    }
  }

  const customCssRaw = typeof value.customCssRaw === 'string' ? value.customCssRaw : '';
  let safeMode: SafeMode = 'balanced';
  if (typeof value.safeMode === 'string') {
    const normalizedSafeMode = assisted ? normalizeSafeMode(value.safeMode) : (isSafeMode(value.safeMode) ? value.safeMode : null);
    if (normalizedSafeMode) {
      safeMode = normalizedSafeMode;
      if (assisted && value.safeMode !== normalizedSafeMode) {
        fixes.push({ entity: 'banner', index, field: 'safeMode', from: value.safeMode, to: normalizedSafeMode });
      }
    }
  }

  return {
    value: {
      id,
      title,
      subtitle,
      conditions: normalizedConditions,
      tags,
      style: normalizedStyle,
      dot: normalizedDot,
      customCssRaw,
      safeMode,
    },
    fixes,
  };
}

function calculateImportPreviewStats(
  mode: ImportMode,
  currentBadges: BadgeCard[],
  currentBanners: BannerCard[],
  importedBadges: BadgeCard[],
  importedBanners: BannerCard[],
): ImportPreviewStats {
  if (mode === 'replace') {
    return {
      badgeUpdated: 0,
      badgeAdded: 0,
      badgeReplaced: importedBadges.length,
      bannerUpdated: 0,
      bannerAdded: 0,
      bannerReplaced: importedBanners.length,
    };
  }

  const badgeMerge = mergeById(currentBadges, importedBadges);
  const bannerMerge = mergeById(currentBanners, importedBanners);

  return {
    badgeUpdated: badgeMerge.updated,
    badgeAdded: badgeMerge.added,
    badgeReplaced: 0,
    bannerUpdated: bannerMerge.updated,
    bannerAdded: bannerMerge.added,
    bannerReplaced: 0,
  };
}

function parseImportData(rawBadges: unknown[], rawBanners: unknown[], assisted: boolean): ParsedImportData {
  const badgeValidation = rawBadges.map((entry, index) => validateBadgeEntry(entry, index, assisted));
  const bannerValidation = rawBanners.map((entry, index) => validateBannerEntry(entry, index, assisted));
  const badges = badgeValidation.map((result) => result.value).filter((value): value is BadgeCard => Boolean(value));
  const banners = bannerValidation.map((result) => result.value).filter((value): value is BannerCard => Boolean(value));
  const issues = [...badgeValidation, ...bannerValidation].map((result) => result.issue).filter((value): value is ImportIssue => Boolean(value));
  const fixes = [...badgeValidation, ...bannerValidation].flatMap((result) => result.fixes);
  return { badges, banners, issues, fixes };
}

function downloadTextFile(fileName: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.URL.revokeObjectURL(url);
}

function escapeCsv(value: string): string {
  const escaped = value.replace(/"/g, '""');
  return `"${escaped}"`;
}

function buildImportIssuesCsv(issues: ImportIssue[], fixes: ImportFix[]): string {
  const header = 'kind,entity,row,field,from,to,reason';
  const issueRows = issues.map((issue) => {
    return [
      escapeCsv('issue'),
      escapeCsv(issue.entity),
      escapeCsv(String(issue.index + 1)),
      escapeCsv(''),
      escapeCsv(''),
      escapeCsv(''),
      escapeCsv(issue.reason),
    ].join(',');
  });
  const fixRows = fixes.map((fix) => {
    return [
      escapeCsv('fix'),
      escapeCsv(fix.entity),
      escapeCsv(String(fix.index + 1)),
      escapeCsv(fix.field),
      escapeCsv(fix.from),
      escapeCsv(fix.to),
      escapeCsv(''),
    ].join(',');
  });
  const rows = [...issueRows, ...fixRows];
  return [header, ...rows].join('\n');
}

function buildCorrectedTemplate(
  sourceFile: string,
  mode: ImportMode,
  badges: BadgeCard[],
  banners: BannerCard[],
  issues: ImportIssue[],
  fixes: ImportFix[],
): string {
  const payload = {
    version: FLAIR_EXPORT_VERSION,
    exportedAt: new Date().toISOString(),
    badges,
    banners,
    _fixGuide: {
      sourceFile,
      mode,
      summary: {
        validBadges: badges.length,
        validBanners: banners.length,
        issueCount: issues.length,
        autoFixCount: fixes.length,
      },
      commonFixes: [
        'badge requires id, label, conditions(number), tone(blue|navy|red|orange|green)',
        'banner requires id, title, subtitle, conditions(number), style(sky|deep|sage), dot(green|pink)',
        'safeMode can be strict, balanced, or off',
      ],
      issues: issues.map((issue) => ({
        entity: issue.entity,
        row: issue.index + 1,
        reason: issue.reason,
      })),
      autoFixes: fixes.map((fix) => ({
        entity: fix.entity,
        row: fix.index + 1,
        field: fix.field,
        from: fix.from,
        to: fix.to,
      })),
    },
  };

  return JSON.stringify(payload, null, 2);
}

function App() {
  const [view, setView] = useState<FlairView>('overview');
  const [badges, setBadges] = useState<BadgeCard[]>(() => loadStoredBadges());
  const [banners, setBanners] = useState<BannerCard[]>(() => loadStoredBanners());
  const [editor, setEditor] = useState<EditorState>({ open: false });
  const [importMode, setImportMode] = useState<ImportMode>('replace');
  const [useAutoFixes, setUseAutoFixes] = useState(true);
  const [importSummary, setImportSummary] = useState<ImportSummary | null>(null);
  const [guidanceMessage, setGuidanceMessage] = useState<GuidanceMessage | null>(null);
  const [pendingImport, setPendingImport] = useState<PendingImport | null>(null);
  const importInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    window.localStorage.setItem(BADGES_STORAGE_KEY, JSON.stringify(badges));
  }, [badges]);

  useEffect(() => {
    window.localStorage.setItem(BANNERS_STORAGE_KEY, JSON.stringify(banners));
  }, [banners]);

  const flairTitle = useMemo(() => {
    if (view === 'badges') return 'Badges';
    if (view === 'banners') return 'Banners';
    if (view === 'settings') return 'Settings';
    return 'Flair';
  }, [view]);

  const scopedCss = useMemo(() => {
    const styles = [
      ...badges.map((badge) => buildScopedCss(badge.id, badge.customCssRaw, badge.safeMode)),
      ...banners.map((banner) => buildScopedCss(banner.id, banner.customCssRaw, banner.safeMode)),
    ].filter(Boolean);
    return styles.join('\n');
  }, [badges, banners]);

  const pendingImportStats = useMemo(() => {
    if (!pendingImport) return null;
    const selected = useAutoFixes ? pendingImport.assisted : pendingImport.strict;
    return calculateImportPreviewStats(importMode, badges, banners, selected.badges, selected.banners);
  }, [pendingImport, useAutoFixes, importMode, badges, banners]);

  const selectedPendingData = useMemo(() => {
    if (!pendingImport) return null;
    return useAutoFixes ? pendingImport.assisted : pendingImport.strict;
  }, [pendingImport, useAutoFixes]);

  const ensureEditorCanClose = (): boolean => {
    if (!editor.open) return true;
    if (!isEditorDirty(editor)) return true;
    return window.confirm('You have unsaved editor changes. Discard them?');
  };

  const closeEditor = () => {
    setEditor({ open: false });
  };

  const navigateTo = (nextView: FlairView) => {
    if (!ensureEditorCanClose()) return;
    closeEditor();
    setView(nextView);
  };

  const openExternal = (url: string) => {
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  const resolveShopDomain = (): string => {
    const params = new URLSearchParams(window.location.search);
    const fromQuery = (params.get('shop') ?? '').trim().toLowerCase();
    if (/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(fromQuery)) return fromQuery;
    return '';
  };

  const openShopifyAdminPath = (path: string) => {
    const shop = resolveShopDomain();
    if (!shop) {
      setGuidanceMessage({
        tone: 'warning',
        title: 'Shop domain not detected',
        detail: 'Unable to open Shopify Admin path because the current URL has no valid shop parameter.',
      });
      return;
    }

    const target = `https://${shop}${path}`;
    window.open(target, '_top');
  };

  const handleShopifyNav = (item: typeof appNav[number]) => {
    if (item === 'Home') {
      navigateTo('overview');
      return;
    }

    const paths: Partial<Record<typeof appNav[number], string>> = {
      Orders: '/admin/orders',
      Products: '/admin/products',
      Customers: '/admin/customers',
      Marketing: '/admin/marketing',
      Discounts: '/admin/discounts',
      Content: '/admin/content',
      Markets: '/admin/settings/markets',
      Finance: '/admin/settings/payments',
      Analytics: '/admin/reports',
    };

    const path = paths[item];
    if (!path) {
      navigateTo('overview');
      return;
    }

    openShopifyAdminPath(path);
  };

  const openBadgeEditor = (index: number) => {
    if (!ensureEditorCanClose()) return;
    const draft = { ...badges[index] };
    setEditor({ open: true, kind: 'badge', index, draft, original: { ...draft } });
  };

  const openBannerEditor = (index: number) => {
    if (!ensureEditorCanClose()) return;
    const draft = { ...banners[index] };
    setEditor({ open: true, kind: 'banner', index, draft, original: { ...draft } });
  };

  const createBadge = () => {
    if (!ensureEditorCanClose()) return;
    const draft: BadgeCard = {
      id: `badge_${Date.now()}`,
      label: 'NEW BADGE',
      conditions: 1,
      tone: 'blue',
      customCssRaw: '',
      safeMode: 'balanced',
    };
    setEditor({
      open: true,
      kind: 'badge',
      index: -1,
      draft,
      original: { ...draft },
    });
  };

  const createBanner = () => {
    if (!ensureEditorCanClose()) return;
    const draft: BannerCard = {
      id: `banner_${Date.now()}`,
      title: 'NEW BANNER',
      subtitle: 'Add your banner copy here.',
      conditions: 1,
      style: 'sky',
      dot: 'green',
      tags: 0,
      customCssRaw: '',
      safeMode: 'balanced',
    };
    setEditor({
      open: true,
      kind: 'banner',
      index: -1,
      draft,
      original: { ...draft },
    });
  };

  const resetBadgesToDefaults = () => {
    if (!window.confirm('Reset all badges and badge CSS to defaults?')) return;
    if (!ensureEditorCanClose()) return;
    setBadges(createDefaultBadges());
    closeEditor();
  };

  const resetBannersToDefaults = () => {
    if (!window.confirm('Reset all banners and banner CSS to defaults?')) return;
    if (!ensureEditorCanClose()) return;
    setBanners(createDefaultBanners());
    closeEditor();
  };

  const resetAllFlairData = () => {
    if (!window.confirm('Reset all Flair badges, banners, and custom CSS to defaults?')) return;
    if (!ensureEditorCanClose()) return;
    setBadges(createDefaultBadges());
    setBanners(createDefaultBanners());
    closeEditor();
    setView('overview');
  };

  const exportFlairConfig = () => {
    const payload: FlairConfigExport = {
      version: FLAIR_EXPORT_VERSION,
      exportedAt: new Date().toISOString(),
      badges,
      banners,
    };

    const dateStamp = new Date().toISOString().replace(/[:.]/g, '-');
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `flair-config-${dateStamp}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.URL.revokeObjectURL(url);

    setGuidanceMessage({
      tone: 'success',
      title: 'Export complete',
      detail: 'Your Flair configuration JSON has been downloaded. Keep this file as a backup before large edits.',
    });
  };

  const triggerImportFlairConfig = () => {
    if (!ensureEditorCanClose()) return;
    importInputRef.current?.click();
  };

  const importFlairConfig: ChangeEventHandler<HTMLInputElement> = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;

    if (!ensureEditorCanClose()) return;

    try {
      if (!file.name.toLowerCase().endsWith('.json')) {
        setGuidanceMessage({
          tone: 'error',
          title: 'Import blocked',
          detail: 'Please select a .json export file. Other file types are not supported.',
        });
        return;
      }

      const raw = await file.text();
      if (!raw.trim().startsWith('{')) {
        setGuidanceMessage({
          tone: 'error',
          title: 'Import blocked',
          detail: 'This file does not look like a Flair JSON export. Use Export Flair config from Settings first.',
        });
        return;
      }

      const parsed = JSON.parse(raw) as Partial<FlairConfigExport>;
      if (typeof parsed.version === 'number' && parsed.version > FLAIR_EXPORT_VERSION) {
        setGuidanceMessage({
          tone: 'warning',
          title: 'Newer export version detected',
          detail: 'Some fields may be ignored because this file was created by a newer export format.',
        });
      }
      const rawBadges = Array.isArray(parsed.badges) ? parsed.badges : [];
      const rawBanners = Array.isArray(parsed.banners) ? parsed.banners : [];

      const strict = parseImportData(rawBadges, rawBanners, false);
      const assisted = parseImportData(rawBadges, rawBanners, true);

      if (strict.badges.length === 0 && strict.banners.length === 0 && assisted.badges.length === 0 && assisted.banners.length === 0) {
        setGuidanceMessage({
          tone: 'error',
          title: 'Import failed',
          detail: 'No valid badges or banners were found. Check that the file contains badges[] or banners[] with valid ids and fields.',
        });
        return;
      }

      setPendingImport({
        fileName: file.name,
        strict,
        assisted,
      });
      setUseAutoFixes(true);
      setView('settings');
      setGuidanceMessage({
        tone: 'info',
        title: 'Import preview ready',
        detail: 'Review strict vs assisted preview and apply when you are ready.',
      });
    } catch {
      setGuidanceMessage({
        tone: 'error',
        title: 'Import failed',
        detail: 'Invalid JSON format. Open the file and verify valid JSON syntax with matching braces and quotes.',
      });
    }
  };

  const applyPendingImport = () => {
    if (!pendingImport || !pendingImportStats) return;

    const selected = useAutoFixes ? pendingImport.assisted : pendingImport.strict;

    const skippedBadges = selected.issues.filter((issue) => issue.entity === 'badge').length;
    const skippedBanners = selected.issues.filter((issue) => issue.entity === 'banner').length;

    if (selected.badges.length === 0 && selected.banners.length === 0) {
      setGuidanceMessage({
        tone: 'error',
        title: 'Nothing to import',
        detail: 'Current preflight mode has no valid rows. Enable auto-fixes or correct source data first.',
      });
      return;
    }

    const summaryBase: ImportSummary = {
      fileName: pendingImport.fileName,
      mode: importMode,
      badgeUpdated: pendingImportStats.badgeUpdated,
      badgeAdded: pendingImportStats.badgeAdded,
      badgeReplaced: pendingImportStats.badgeReplaced,
      bannerUpdated: pendingImportStats.bannerUpdated,
      bannerAdded: pendingImportStats.bannerAdded,
      bannerReplaced: pendingImportStats.bannerReplaced,
      skippedBadges,
      skippedBanners,
    };

    if (importMode === 'replace') {
      if (selected.badges.length > 0) {
        setBadges(selected.badges);
      }
      if (selected.banners.length > 0) {
        setBanners(selected.banners);
      }
    } else {
      if (selected.badges.length > 0) {
        const merged = mergeById(badges, selected.badges);
        setBadges(merged.next);
      }
      if (selected.banners.length > 0) {
        const merged = mergeById(banners, selected.banners);
        setBanners(merged.next);
      }
    }

    setImportSummary(summaryBase);
    setPendingImport(null);
    closeEditor();
    setView('overview');

    if (skippedBadges > 0 || skippedBanners > 0) {
      setGuidanceMessage({
        tone: 'warning',
        title: 'Import completed with skips',
        detail: `Skipped ${skippedBadges} badge entries and ${skippedBanners} banner entries due to invalid structure.`,
      });
    } else {
      setGuidanceMessage({
        tone: 'success',
        title: 'Import complete',
        detail: 'Configuration applied successfully. Review cards in Badges and Banners to confirm styling and targeting.',
      });
    }
  };

  const cancelPendingImport = () => {
    setPendingImport(null);
    setGuidanceMessage({
      tone: 'info',
      title: 'Import preview canceled',
      detail: 'No changes were applied. You can re-import anytime from Settings.',
    });
  };

  const downloadPendingImportIssueReport = (format: 'json' | 'csv') => {
    if (!pendingImport) return;

    const selected = useAutoFixes ? pendingImport.assisted : pendingImport.strict;

    const baseName = pendingImport.fileName.replace(/\.[^.]+$/, '');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');

    if (format === 'json') {
      const payload = {
        sourceFile: pendingImport.fileName,
        mode: importMode,
        preflightMode: useAutoFixes ? 'assisted' : 'strict',
        generatedAt: new Date().toISOString(),
        issueCount: selected.issues.length,
        autoFixCount: selected.fixes.length,
        issues: selected.issues.map((issue) => ({
          entity: issue.entity,
          row: issue.index + 1,
          reason: issue.reason,
        })),
        autoFixes: selected.fixes.map((fix) => ({
          entity: fix.entity,
          row: fix.index + 1,
          field: fix.field,
          from: fix.from,
          to: fix.to,
        })),
      };
      downloadTextFile(
        `${baseName}-import-issues-${stamp}.json`,
        JSON.stringify(payload, null, 2),
        'application/json',
      );
    } else {
      const csv = buildImportIssuesCsv(selected.issues, selected.fixes);
      downloadTextFile(`${baseName}-import-issues-${stamp}.csv`, csv, 'text/csv;charset=utf-8');
    }

    setGuidanceMessage({
      tone: 'success',
      title: 'Issue report downloaded',
      detail: `Downloaded ${selected.issues.length} validation issue(s) as ${format.toUpperCase()}.`,
    });
  };

  const downloadPendingImportCorrectedTemplate = () => {
    if (!pendingImport) return;

    const selected = useAutoFixes ? pendingImport.assisted : pendingImport.strict;

    const baseName = pendingImport.fileName.replace(/\.[^.]+$/, '');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const corrected = buildCorrectedTemplate(
      pendingImport.fileName,
      importMode,
      selected.badges,
      selected.banners,
      selected.issues,
      selected.fixes,
    );

    downloadTextFile(
      `${baseName}-corrected-template-${stamp}.json`,
      corrected,
      'application/json',
    );

    setGuidanceMessage({
      tone: 'success',
      title: 'Corrected template downloaded',
      detail: 'Downloaded a cleaned import template with valid rows and a fix guide for skipped rows.',
    });
  };

  const saveEditor = () => {
    if (!editor.open) return;
    if (editor.kind === 'badge') {
      setBadges((current) => {
        if (editor.index < 0) return [editor.draft, ...current];
        return current.map((item, idx) => (idx === editor.index ? editor.draft : item));
      });
    } else {
      setBanners((current) => {
        if (editor.index < 0) return [editor.draft, ...current];
        return current.map((item, idx) => (idx === editor.index ? editor.draft : item));
      });
    }
    setEditor({ open: false });
  };

  return (
    <div className="gcw-admin-shell">
      <div className="gcw-body">
        <aside className="gcw-sidebar">
          <ul className="gcw-sidebar-list">
            {appNav.map((item) => (
              <li key={item}>
                <button type="button" className="gcw-sidebar-item" onClick={() => handleShopifyNav(item)}>
                  {item}
                </button>
              </li>
            ))}
          </ul>

          <div className="gcw-apps-label">Apps</div>
          <div className="gcw-flair-group">
            <button type="button" className={`gcw-flair-item ${view === 'overview' ? 'active' : ''}`} onClick={() => navigateTo('overview')} aria-current={view === 'overview'}>
              Flair
            </button>
            <button type="button" className={`gcw-flair-subitem ${view === 'badges' ? 'active' : ''}`} onClick={() => navigateTo('badges')} aria-current={view === 'badges'}>
              Badges
            </button>
            <button type="button" className={`gcw-flair-subitem ${view === 'banners' ? 'active' : ''}`} onClick={() => navigateTo('banners')} aria-current={view === 'banners'}>
              Banners
            </button>
            <button type="button" className={`gcw-flair-subitem ${view === 'settings' ? 'active' : ''}`} onClick={() => navigateTo('settings')} aria-current={view === 'settings'}>
              Settings
            </button>
          </div>
        </aside>

        <main className="gcw-content">
          <div className="gcw-app-label-row">
            <span className="gcw-app-icon">F</span>
            <span className="gcw-app-label">Flair</span>
          </div>
          <div className="gcw-page-head">
            <h1>{flairTitle}</h1>
            {(view === 'badges' || view === 'banners') && (
              <div className="gcw-page-actions">
                <button type="button" className="gcw-secondary-btn" onClick={() => navigateTo('settings')}>Layouts</button>
                <button
                  type="button"
                  className="gcw-secondary-btn gcw-danger-btn"
                  onClick={() => (view === 'badges' ? resetBadgesToDefaults() : resetBannersToDefaults())}
                >
                  Reset {view === 'badges' ? 'badges' : 'banners'}
                </button>
                <button type="button" className="gcw-primary-btn" onClick={() => (view === 'badges' ? createBadge() : createBanner())}>+ Add {view === 'badges' ? 'badge' : 'banner'}</button>
              </div>
            )}
          </div>

          {guidanceMessage ? (
            <GuidanceNotice
              message={guidanceMessage}
              onDismiss={() => setGuidanceMessage(null)}
            />
          ) : null}

          {importSummary ? (
            <ImportSummaryNotice summary={importSummary} onDismiss={() => setImportSummary(null)} />
          ) : null}

          {pendingImport && pendingImportStats && selectedPendingData ? (
            <ImportPreflightNotice
              fileName={pendingImport.fileName}
              mode={importMode}
              useAutoFixes={useAutoFixes}
              onToggleAutoFixes={setUseAutoFixes}
              strictCounts={{ badges: pendingImport.strict.badges.length, banners: pendingImport.strict.banners.length }}
              assistedCounts={{ badges: pendingImport.assisted.badges.length, banners: pendingImport.assisted.banners.length }}
              stats={pendingImportStats}
              issues={selectedPendingData.issues}
              fixes={selectedPendingData.fixes}
              onApply={applyPendingImport}
              onCancel={cancelPendingImport}
              onDownloadJson={() => downloadPendingImportIssueReport('json')}
              onDownloadCsv={() => downloadPendingImportIssueReport('csv')}
              onDownloadTemplate={downloadPendingImportCorrectedTemplate}
            />
          ) : null}

          {editor.open && (
            <CampaignStyleEditor
              editor={editor}
              onChange={setEditor}
              onSave={saveEditor}
              onCancel={closeEditor}
            />
          )}

          {scopedCss && <style>{scopedCss}</style>}

          {view === 'overview' && <OverviewView onNavigate={navigateTo} />}
          {view === 'badges' && <BadgesView cards={badges} onEdit={openBadgeEditor} />}
          {view === 'banners' && <BannersView cards={banners} onEdit={openBannerEditor} />}
          {view === 'settings' && (
            <SettingsView
              onResetAll={resetAllFlairData}
              onExport={exportFlairConfig}
              onImport={triggerImportFlairConfig}
              importMode={importMode}
              onImportModeChange={setImportMode}
              onThemeSetup={() => openShopifyAdminPath('/admin/themes/current/editor')}
              onThemeTriggers={() => navigateTo('banners')}
              onBillingPlan={() => openShopifyAdminPath('/admin/charges')}
              onLanguages={() => openShopifyAdminPath('/admin/settings/languages')}
              onFlairGeneration={() => openExternal('https://help.shopify.com/en/manual/promoting-marketing')}
            />
          )}

          <input
            ref={importInputRef}
            type="file"
            accept="application/json,.json"
            onChange={importFlairConfig}
            className="gcw-hidden-file-input"
            title="Import Flair configuration"
            aria-label="Import Flair configuration"
          />
        </main>
      </div>
    </div>
  );
}

function ImportSummaryNotice({ summary, onDismiss }: { summary: ImportSummary; onDismiss: () => void }) {
  const modeLabel = summary.mode === 'replace' ? 'Replace mode' : 'Merge mode';

  return (
    <section className="gcw-import-summary" role="status" aria-live="polite">
      <div className="gcw-import-summary-head">
        <h2>Import complete</h2>
        <span>{modeLabel}</span>
      </div>
      <p className="gcw-import-summary-file">{summary.fileName}</p>
      <div className="gcw-import-summary-grid">
        <p>
          <strong>Badges:</strong>{' '}
          {summary.mode === 'replace'
            ? `${summary.badgeReplaced} replaced`
            : `${summary.badgeUpdated} updated, ${summary.badgeAdded} added`}
        </p>
        <p>
          <strong>Banners:</strong>{' '}
          {summary.mode === 'replace'
            ? `${summary.bannerReplaced} replaced`
            : `${summary.bannerUpdated} updated, ${summary.bannerAdded} added`}
        </p>
        <p><strong>Skipped badges:</strong> {summary.skippedBadges}</p>
        <p><strong>Skipped banners:</strong> {summary.skippedBanners}</p>
      </div>
      <div className="gcw-import-summary-actions">
        <button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onDismiss}>Dismiss</button>
      </div>
    </section>
  );
}

function GuidanceNotice({ message, onDismiss }: { message: GuidanceMessage; onDismiss: () => void }) {
  return (
    <section className={`gcw-guidance-notice gcw-guidance-notice--${message.tone}`} role="status" aria-live="polite">
      <div className="gcw-guidance-notice-head">
        <h2>{message.title}</h2>
        <button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onDismiss}>Dismiss</button>
      </div>
      <p>{message.detail}</p>
    </section>
  );
}

function buildScopedCss(id: string, rawCss: string, safeMode: SafeMode): string {
  let css = rawCss.trim();
  if (!css) return '';

  if (safeMode !== 'off') {
    css = css
      .replace(/@import[^;]+;?/gi, '')
      .replace(/expression\s*\(/gi, '')
      .replace(/url\s*\(\s*['\"]?javascript:[^)]+\)/gi, '');
  }

  if (safeMode === 'strict') {
    css = css
      .replace(/position\s*:\s*(fixed|sticky)\s*;?/gi, '')
      .replace(/z-index\s*:\s*\d+\s*;?/gi, '');
  }

  const scope = `.flair-campaign-${id}`;

  if (!css.includes('{')) {
    return `${scope} {\n${css}\n}`;
  }

  if (css.includes('.flair-campaign')) {
    return css.replace(/\.flair-campaign\b/g, scope);
  }

  return css;
}

function OverviewView({ onNavigate }: { onNavigate: (view: FlairView) => void }) {
  return (
    <section className="gcw-overview-grid">
      <article className="gcw-card gcw-summary-card">
        <div className="gcw-card-head">
          <h2>Badges</h2>
          <button type="button" className="gcw-secondary-btn" onClick={() => onNavigate('badges')}>View badges</button>
        </div>
        <div className="gcw-summary-body">
          <ul className="gcw-summary-list">
            <li><span className="dot green" /> 16 Published</li>
            <li><span className="dot amber" /> 4 Scheduled</li>
            <li><span className="dot gray" /> 264 Unpublished</li>
          </ul>
          <div className="gcw-summary-visual">50% off</div>
        </div>
      </article>

      <article className="gcw-card gcw-summary-card">
        <div className="gcw-card-head">
          <h2>Banners</h2>
          <button type="button" className="gcw-secondary-btn" onClick={() => onNavigate('banners')}>View banners</button>
        </div>
        <div className="gcw-summary-body">
          <ul className="gcw-summary-list">
            <li><span className="dot green" /> 10 Published</li>
            <li><span className="dot amber" /> 2 Scheduled</li>
            <li><span className="dot gray" /> 197 Unpublished</li>
          </ul>
          <div className="gcw-summary-visual gcw-summary-visual--banner">Free Shipping</div>
        </div>
      </article>

      <article className="gcw-card">
        <h2>Theme status</h2>
        <p><span className="dot green" /> Flair is enabled</p>
        <p>2 blocks detected</p>
        <button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={() => onNavigate('settings')}>View</button>
      </article>

      <article className="gcw-card">
        <h2>Product updates</h2>
        <p>February 2026</p>
        <p>Flair Promotions Now Support Native Translations</p>
        <button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={() => onNavigate('settings')}>Open settings</button>
      </article>

      <article className="gcw-card">
        <h2>Need some inspiration?</h2>
        <p>Browse the Flair gallery to quickly get started with customizable badge and banner templates.</p>
        <button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={() => onNavigate('badges')}>Visit the gallery</button>
      </article>

      <article className="gcw-card gcw-help-card">
        <h2>Help center</h2>
        <div className="gcw-help-layout">
          <ul>
            <li><button type="button" className="gcw-help-link" onClick={() => onNavigate('badges')}>How to get started with Flair</button></li>
            <li><button type="button" className="gcw-help-link" onClick={() => onNavigate('banners')}>How to run a Flair promotion</button></li>
            <li><button type="button" className="gcw-help-link" onClick={() => onNavigate('settings')}>How to troubleshoot Flair</button></li>
          </ul>
          <article className="gcw-blog-card">
            <h4>FROM THE BLOG</h4>
            <p>How to Sell on Shopify - Probably The Most Useful Guide You'll Read</p>
          </article>
        </div>
      </article>
    </section>
  );
}

function BadgesView({ cards, onEdit }: { cards: BadgeCard[]; onEdit: (index: number) => void }) {
  const [sortAlpha, setSortAlpha] = useState(false);
  const [showHighConditionOnly, setShowHighConditionOnly] = useState(false);

  const visibleCards = useMemo(() => {
    const nextCards = cards
      .filter((card) => !showHighConditionOnly || card.conditions >= 3)
      .slice();

    if (sortAlpha) {
      nextCards.sort((left, right) => left.label.localeCompare(right.label));
    }

    return nextCards;
  }, [cards, showHighConditionOnly, sortAlpha]);

  return (
    <section>
      <div className="gcw-filters-row">
        <button type="button" className="gcw-secondary-btn" onClick={() => setShowHighConditionOnly((current) => !current)}>
          {showHighConditionOnly ? 'Showing 3+ only' : 'Filter'}
        </button>
        <button type="button" className="gcw-secondary-btn" onClick={() => setSortAlpha((current) => !current)}>
          {sortAlpha ? 'Sorted A-Z' : 'Sort'}
        </button>
      </div>
      <div className="gcw-badge-grid">
        {visibleCards.map((card) => {
          const cardIndex = cards.findIndex((entry) => entry.id === card.id);
          return (
          <article key={card.id} className="gcw-badge-card">
            <div className="gcw-badge-preview">
              <span className={`gcw-chip ${card.tone} flair-campaign-${card.id}`}>{card.label}</span>
              <button type="button" className="gcw-kebab" onClick={() => onEdit(cardIndex)} aria-label={`Edit badge ${card.label}`}>⋮</button>
            </div>
            <div className="gcw-badge-meta">
              <span className="dot green" />
              <span>{card.conditions} conditions</span>
            </div>
          </article>
        )})}
      </div>
    </section>
  );
}

function BannersView({ cards, onEdit }: { cards: BannerCard[]; onEdit: (index: number) => void }) {
  const [sortAlpha, setSortAlpha] = useState(false);
  const [showPinkOnly, setShowPinkOnly] = useState(false);

  const visibleCards = useMemo(() => {
    const nextCards = cards
      .filter((card) => !showPinkOnly || card.dot === 'pink')
      .slice();

    if (sortAlpha) {
      nextCards.sort((left, right) => left.title.localeCompare(right.title));
    }

    return nextCards;
  }, [cards, showPinkOnly, sortAlpha]);

  return (
    <section>
      <div className="gcw-filters-row">
        <button type="button" className="gcw-secondary-btn" onClick={() => setShowPinkOnly((current) => !current)}>
          {showPinkOnly ? 'Showing pink only' : 'Filter'}
        </button>
        <button type="button" className="gcw-secondary-btn" onClick={() => setSortAlpha((current) => !current)}>
          {sortAlpha ? 'Sorted A-Z' : 'Sort'}
        </button>
      </div>
      <div className="gcw-banner-grid">
        {visibleCards.map((card) => {
          const cardIndex = cards.findIndex((entry) => entry.id === card.id);
          return (
          <article key={card.id} className="gcw-banner-card">
            <div className={`gcw-banner-preview ${card.style} flair-campaign-${card.id}`}>
              <h3>{card.title}</h3>
              <p>{card.subtitle}</p>
            </div>
            <div className="gcw-banner-meta">
              <span className={`dot ${card.dot}`} />
              <span>{card.conditions} conditions</span>
              {card.tags ? <span>{card.tags} tag</span> : null}
              <button type="button" className="gcw-kebab gcw-kebab-inline" onClick={() => onEdit(cardIndex)} aria-label={`Edit banner ${card.title}`}>⋮</button>
            </div>
          </article>
        )})}
      </div>
    </section>
  );
}

function CampaignStyleEditor({
  editor,
  onChange,
  onSave,
  onCancel,
}: {
  editor: Extract<EditorState, { open: true }>;
  onChange: (next: EditorState) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  const scope = `.flair-campaign-${editor.draft.id}`;
  const badgeDraft = editor.kind === 'badge' ? editor.draft : null;
  const bannerDraft = editor.kind === 'banner' ? editor.draft : null;
  const hasUnsavedChanges = useMemo(() => isEditorDirty(editor), [editor]);
  const cssWarnings = useMemo(
    () => getCssWarnings(editor.draft.customCssRaw, editor.draft.safeMode),
    [editor.draft.customCssRaw, editor.draft.safeMode],
  );

  const handleCancel = () => {
    if (hasUnsavedChanges && !window.confirm('Discard unsaved editor changes?')) return;
    onCancel();
  };

  const setBadgeDraft = (nextDraft: BadgeCard) => {
    if (editor.kind !== 'badge') return;
    onChange({ ...editor, draft: nextDraft });
  };

  const setBannerDraft = (nextDraft: BannerCard) => {
    if (editor.kind !== 'banner') return;
    onChange({ ...editor, draft: nextDraft });
  };

  const appendCssSnippet = (snippet: string) => {
    const current = editor.draft.customCssRaw;
    const nextCss = `${current}${current ? '\n' : ''}${snippet}`;
    if (editor.kind === 'badge') {
      setBadgeDraft({ ...editor.draft, customCssRaw: nextCss });
    } else {
      setBannerDraft({ ...editor.draft, customCssRaw: nextCss });
    }
  };

  return (
    <section className="gcw-editor-panel">
      <div className="gcw-editor-head">
        <h2>
          {editor.kind === 'badge' ? 'Edit badge' : 'Edit banner'} style
          {hasUnsavedChanges ? <span className="gcw-editor-dirty">Unsaved changes</span> : null}
        </h2>
        <div className="gcw-editor-actions">
          <button type="button" className="gcw-secondary-btn" onClick={handleCancel}>Cancel</button>
          <button type="button" className="gcw-primary-btn" onClick={onSave}>Save</button>
        </div>
      </div>

      <div className="gcw-editor-grid">
        <div className="gcw-editor-fields">
          {editor.kind === 'badge' ? (
            <label className="gcw-field-label">
              Badge text
              <input
                type="text"
                value={editor.draft.label}
                  onChange={(event) => setBadgeDraft({ ...editor.draft, label: event.target.value })}
              />
            </label>
          ) : (
            <>
              <label className="gcw-field-label">
                Banner title
                <input
                  type="text"
                  value={editor.draft.title}
                  onChange={(event) => setBannerDraft({ ...editor.draft, title: event.target.value })}
                />
              </label>
              <label className="gcw-field-label">
                Banner subtitle
                <input
                  type="text"
                  value={editor.draft.subtitle}
                  onChange={(event) => setBannerDraft({ ...editor.draft, subtitle: event.target.value })}
                />
              </label>
            </>
          )}

          <label className="gcw-field-label">
            Conditions
            <input
              type="number"
              min={0}
              value={editor.draft.conditions}
              onChange={(event) => {
                const nextConditions = Number(event.target.value) || 0;
                if (editor.kind === 'badge') {
                  setBadgeDraft({ ...editor.draft, conditions: nextConditions });
                } else {
                  setBannerDraft({ ...editor.draft, conditions: nextConditions });
                }
              }}
            />
          </label>

          {editor.kind === 'badge' && badgeDraft ? (
            <label className="gcw-field-label">
              Badge style
              <select
                value={badgeDraft.tone}
                onChange={(event) => setBadgeDraft({ ...badgeDraft, tone: event.target.value as BadgeCard['tone'] })}
              >
                <option value="blue">Blue</option>
                <option value="navy">Navy</option>
                <option value="red">Red</option>
                <option value="orange">Orange</option>
                <option value="green">Green</option>
              </select>
            </label>
          ) : (
            <label className="gcw-field-label">
              Banner style
              <select
                value={bannerDraft?.style ?? 'sky'}
                onChange={(event) => bannerDraft && setBannerDraft({ ...bannerDraft, style: event.target.value as BannerCard['style'] })}
              >
                <option value="sky">Sky</option>
                <option value="deep">Deep</option>
                <option value="sage">Sage</option>
              </select>
            </label>
          )}

          <label className="gcw-field-label">
            Safety mode
            <select
              value={editor.draft.safeMode}
              onChange={(event) => {
                const nextSafeMode = event.target.value as SafeMode;
                if (editor.kind === 'badge') {
                  setBadgeDraft({ ...editor.draft, safeMode: nextSafeMode });
                } else {
                  setBannerDraft({ ...editor.draft, safeMode: nextSafeMode });
                }
              }}
            >
              <option value="strict">Strict</option>
              <option value="balanced">Balanced</option>
              <option value="off">Off</option>
            </select>
          </label>
        </div>

        <div className="gcw-editor-css">
          <div className="css-code-box">
            <div className="css-code-box-header">
              <span>CSS</span>
              <span className="css-code-box-scope">{scope}</span>
            </div>
            <textarea
              className="css-code-textarea"
              rows={12}
              value={editor.draft.customCssRaw}
              onChange={(event) => {
                const nextCss = event.target.value;
                if (editor.kind === 'badge') {
                  setBadgeDraft({ ...editor.draft, customCssRaw: nextCss });
                } else {
                  setBannerDraft({ ...editor.draft, customCssRaw: nextCss });
                }
              }}
              placeholder={`.flair-campaign {\n  border-radius: 12px;\n  box-shadow: 0 6px 18px rgba(17, 37, 63, 0.18);\n}`}
              spellCheck={false}
            />
            <div className="css-code-footer">
              <button type="button" className="css-snippet-btn" onClick={() => appendCssSnippet(`.flair-campaign {\n  border-radius: 14px;\n}`)}>
                + Rounded corners
              </button>
              <button type="button" className="css-snippet-btn" onClick={() => appendCssSnippet(`.flair-campaign {\n  text-transform: uppercase;\n  letter-spacing: 0.06em;\n}`)}>
                + Bold headline
              </button>
              <button type="button" className="css-snippet-btn" onClick={() => appendCssSnippet(`.flair-campaign {\n  animation: flair-pulse 1.8s ease-in-out infinite;\n}\n@keyframes flair-pulse {\n  0%, 100% { opacity: 1; }\n  50% { opacity: 0.65; }\n}`)}>
                + Pulse
              </button>
              <button
                type="button"
                className="css-snippet-btn css-snippet-btn--clear"
                onClick={() => {
                  if (editor.kind === 'badge') {
                    setBadgeDraft({ ...editor.draft, customCssRaw: '' });
                  } else {
                    setBannerDraft({ ...editor.draft, customCssRaw: '' });
                  }
                }}
              >
                Clear
              </button>
            </div>
          </div>

          {cssWarnings.length > 0 ? (
            <ul className="gcw-css-warnings" aria-live="polite">
              {cssWarnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}

          <div className="gcw-editor-preview">
            {'tone' in editor.draft ? (
              <span className={`gcw-chip ${editor.draft.tone} flair-campaign-${editor.draft.id}`}>{editor.draft.label || 'Badge preview'}</span>
            ) : (
              <div className={`gcw-banner-preview ${editor.draft.style} flair-campaign-${editor.draft.id}`}>
                <h3>{editor.draft.title || 'Banner preview'}</h3>
                <p>{editor.draft.subtitle || 'Banner subtitle'}</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function ImportPreflightNotice({
  fileName,
  mode,
  useAutoFixes,
  onToggleAutoFixes,
  strictCounts,
  assistedCounts,
  stats,
  issues,
  fixes,
  onApply,
  onCancel,
  onDownloadJson,
  onDownloadCsv,
  onDownloadTemplate,
}: {
  fileName: string;
  mode: ImportMode;
  useAutoFixes: boolean;
  onToggleAutoFixes: (next: boolean) => void;
  strictCounts: { badges: number; banners: number };
  assistedCounts: { badges: number; banners: number };
  stats: ImportPreviewStats;
  issues: ImportIssue[];
  fixes: ImportFix[];
  onApply: () => void;
  onCancel: () => void;
  onDownloadJson: () => void;
  onDownloadCsv: () => void;
  onDownloadTemplate: () => void;
}) {
  const badgeIssues = issues.filter((issue) => issue.entity === 'badge');
  const bannerIssues = issues.filter((issue) => issue.entity === 'banner');
  const topIssues = issues.slice(0, 8);
  const topFixes = fixes.slice(0, 8);
  const recoveredBadges = Math.max(0, assistedCounts.badges - strictCounts.badges);
  const recoveredBanners = Math.max(0, assistedCounts.banners - strictCounts.banners);

  return (
    <section className="gcw-preflight" role="status" aria-live="polite">
      <div className="gcw-preflight-head">
        <h2>Import preflight validation</h2>
        <span>{mode === 'replace' ? 'Replace mode' : 'Merge mode'}</span>
      </div>
      <p className="gcw-preflight-mode-diff">
        Assisted recovery potential: <strong>+{recoveredBadges}</strong> additional valid badge row(s), <strong>+{recoveredBanners}</strong> additional valid banner row(s).
      </p>
      <label className="gcw-preflight-toggle">
        <input type="checkbox" checked={useAutoFixes} onChange={(event) => onToggleAutoFixes(event.target.checked)} />
        Apply assisted auto-fixes
      </label>
      <p className="gcw-preflight-file">{fileName}</p>

      <div className="gcw-preflight-grid">
        <p>
          <strong>Badges:</strong>{' '}
          {mode === 'replace'
            ? `${stats.badgeReplaced} will be replaced`
            : `${stats.badgeUpdated} will update, ${stats.badgeAdded} will add`}
        </p>
        <p>
          <strong>Banners:</strong>{' '}
          {mode === 'replace'
            ? `${stats.bannerReplaced} will be replaced`
            : `${stats.bannerUpdated} will update, ${stats.bannerAdded} will add`}
        </p>
        <p><strong>Skipped badge rows:</strong> {badgeIssues.length}</p>
        <p><strong>Skipped banner rows:</strong> {bannerIssues.length}</p>
        <p><strong>Auto-fixed values:</strong> {fixes.length}</p>
      </div>

      {topFixes.length > 0 ? (
        <div className="gcw-preflight-fixes-wrap">
          <h3>Auto-fixes applied (first {topFixes.length})</h3>
          <ul className="gcw-preflight-fixes">
            {topFixes.map((fix) => (
              <li key={`${fix.entity}-${fix.index}-${fix.field}-${fix.from}-${fix.to}`}>
                <strong>{fix.entity} row {fix.index + 1}:</strong> {fix.field} "{fix.from}" {' -> '} "{fix.to}"
              </li>
            ))}
          </ul>
          {fixes.length > topFixes.length ? (
            <p className="gcw-preflight-more">{fixes.length - topFixes.length} more auto-fixes not shown.</p>
          ) : null}
        </div>
      ) : null}

      {topIssues.length > 0 ? (
        <div className="gcw-preflight-issues-wrap">
          <h3>Validation issues (first {topIssues.length})</h3>
          <ul className="gcw-preflight-issues">
            {topIssues.map((issue) => (
              <li key={`${issue.entity}-${issue.index}-${issue.reason}`}>
                <strong>{issue.entity} row {issue.index + 1}:</strong> {issue.reason}
              </li>
            ))}
          </ul>
          {issues.length > topIssues.length ? (
            <p className="gcw-preflight-more">{issues.length - topIssues.length} more issues not shown.</p>
          ) : null}
        </div>
      ) : null}

      <div className="gcw-preflight-actions">
        {issues.length > 0 ? (
          <>
            <button type="button" className="gcw-secondary-btn" onClick={onDownloadTemplate}>Download corrected template</button>
            <button type="button" className="gcw-secondary-btn" onClick={onDownloadJson}>Download issue JSON</button>
            <button type="button" className="gcw-secondary-btn" onClick={onDownloadCsv}>Download issue CSV</button>
          </>
        ) : null}
        <button type="button" className="gcw-secondary-btn" onClick={onCancel}>Cancel import</button>
        <button type="button" className="gcw-primary-btn" onClick={onApply}>Apply import</button>
      </div>
    </section>
  );
}

function SettingsView({
  onResetAll,
  onExport,
  onImport,
  importMode,
  onImportModeChange,
  onThemeSetup,
  onThemeTriggers,
  onBillingPlan,
  onLanguages,
  onFlairGeneration,
}: {
  onResetAll: () => void;
  onExport: () => void;
  onImport: () => void;
  importMode: ImportMode;
  onImportModeChange: (mode: ImportMode) => void;
  onThemeSetup: () => void;
  onThemeTriggers: () => void;
  onBillingPlan: () => void;
  onLanguages: () => void;
  onFlairGeneration: () => void;
}) {
  const [enabled, setEnabled] = useState(true);

  return (
    <section className="gcw-settings-grid">
      <article className="gcw-card">
        <h2>General</h2>
        <ul className="gcw-settings-list">
          <li className="gcw-settings-row">
            <div><span>Flair status</span><strong>Flair is enabled</strong></div>
            <button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={() => setEnabled((current) => !current)}>
              {enabled ? 'Disable' : 'Enable'}
            </button>
          </li>
          <li className="gcw-settings-row"><div><span>Billing plan</span><strong>Grow $49</strong></div><button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onBillingPlan}>Open</button></li>
          <li className="gcw-settings-row"><div><span>Languages</span><strong>No additional languages enabled</strong></div><button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onLanguages}>Open</button></li>
          <li className="gcw-settings-row"><div><span>Flair generation</span><strong>You're using Flair Gen 3.</strong></div><button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onFlairGeneration}>Learn</button></li>
        </ul>
      </article>
      <article className="gcw-card">
        <h2>Theme</h2>
        <ul className="gcw-settings-list">
          <li className="gcw-settings-row"><div><span>Theme setup</span><strong>Configure Flair in your Shopify theme.</strong></div><button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onThemeSetup}>Open</button></li>
          <li className="gcw-settings-row"><div><span>Theme triggers</span><strong>0 triggers configured</strong></div><button type="button" className="gcw-secondary-btn gcw-mini-btn" onClick={onThemeTriggers}>Open</button></li>
        </ul>
        <div className="gcw-settings-transfer-wrap">
          <button type="button" className="gcw-secondary-btn" onClick={onExport}>Export Flair config</button>
          <button type="button" className="gcw-secondary-btn" onClick={onImport}>Import Flair config</button>
        </div>
        <label className="gcw-settings-import-mode">
          Import mode
          <select value={importMode} onChange={(event) => onImportModeChange(event.target.value as ImportMode)}>
            <option value="replace">Replace existing</option>
            <option value="merge">Merge by id</option>
          </select>
        </label>
        <div className="gcw-settings-reset-wrap">
          <button type="button" className="gcw-secondary-btn gcw-danger-btn" onClick={onResetAll}>Reset all Flair data</button>
        </div>

        <div className="gcw-settings-guidance" role="note" aria-label="Import and export guidance">
          <h3>Import and Export Tips</h3>
          <ul>
            <li>Use Export before major edits so you always have a rollback file.</li>
            <li>Use Replace when moving a full environment config.</li>
            <li>Use Merge when you only need to update matching ids and add new campaigns.</li>
            <li>Keep stable ids across stores for predictable merge behavior.</li>
            <li>If entries are skipped, inspect missing id, style, or tone fields in the JSON.</li>
          </ul>
        </div>
      </article>
    </section>
  );
}

export default App;
