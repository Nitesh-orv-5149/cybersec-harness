// Every non-dependency scan kind the workbench knows. Order = display order.
import type { ScanKind } from './types.js';
import { apiKind } from '../api/kind.js';

export const SCAN_KINDS: ScanKind[] = [apiKind];
