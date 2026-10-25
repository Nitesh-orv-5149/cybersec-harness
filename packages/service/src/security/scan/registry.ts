// Every non-dependency scan kind the workbench knows. Order = display order.
import type { ScanKind } from './types.js';
import { apiKind } from '../api/kind.js';
import { secretsKind } from '../secrets/kind.js';
import { iacKind } from '../iac/kind.js';

export const SCAN_KINDS: ScanKind[] = [apiKind, secretsKind, iacKind];
