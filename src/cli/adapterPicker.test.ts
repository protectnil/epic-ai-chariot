/**
 * @epicai/chariot — tests for src/cli/adapterPicker.ts
 * CHARIOT::§17.2::7, ::8, ::9
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { filterAdapters, groupByCategory, getLicenseTierInfoFrom } from './adapterPicker.js';
import type { AdapterEntry } from '../engine/server/ChariotState.js';

function fixtureAdapters(): AdapterEntry[] {
  return [
    { id: 'pubmed', name: 'PubMed', description: 'Search biomedical papers', category: 'Research', keywords: ['medicine', 'health'] } as AdapterEntry,
    { id: 'robtex', name: 'Robtex', description: 'Network intelligence — DNS, IP, ASN', category: 'Security', keywords: ['dns', 'network'] } as AdapterEntry,
    { id: 'govbase-mcp', name: 'Govbase', description: 'Government data', category: 'Research', keywords: [] } as AdapterEntry,
    { id: 'no-category', name: 'Mystery', description: 'no category set' } as AdapterEntry,
  ];
}

describe('filterAdapters — CHARIOT::§17.2::8 (search)', () => {
  it('returns all adapters when no filter is given', () => {
    assert.equal(filterAdapters(fixtureAdapters()).length, 4);
  });

  it('matches on id, case-insensitively', () => {
    const out = filterAdapters(fixtureAdapters(), { search: 'ROBTEX' });
    assert.deepEqual(out.map((a) => a.id), ['robtex']);
  });

  it('matches on description substring', () => {
    const out = filterAdapters(fixtureAdapters(), { search: 'biomedical' });
    assert.deepEqual(out.map((a) => a.id), ['pubmed']);
  });

  it('matches on keywords', () => {
    const out = filterAdapters(fixtureAdapters(), { search: 'dns' });
    assert.deepEqual(out.map((a) => a.id), ['robtex']);
  });

  it('treats an empty/whitespace search as no filter', () => {
    assert.equal(filterAdapters(fixtureAdapters(), { search: '   ' }).length, 4);
  });

  it('combines category and search filters (intersection)', () => {
    const out = filterAdapters(fixtureAdapters(), { category: 'Research', search: 'gov' });
    assert.deepEqual(out.map((a) => a.id), ['govbase-mcp']);
  });

  it('returns empty array when nothing matches (never throws)', () => {
    assert.deepEqual(filterAdapters(fixtureAdapters(), { search: 'zzz-no-match-zzz' }), []);
  });
});

describe('groupByCategory — CHARIOT::§17.2::7 (categorized picker)', () => {
  it('groups adapters under their category', () => {
    const groups = groupByCategory(fixtureAdapters());
    assert.deepEqual(groups.get('Research')?.map((a) => a.id).sort(), ['govbase-mcp', 'pubmed']);
    assert.deepEqual(groups.get('Security')?.map((a) => a.id), ['robtex']);
  });

  it('buckets adapters with no category under "Uncategorized" rather than dropping them', () => {
    const groups = groupByCategory(fixtureAdapters());
    assert.deepEqual(groups.get('Uncategorized')?.map((a) => a.id), ['no-category']);
  });

  it('every input adapter appears in exactly one group', () => {
    const all = fixtureAdapters();
    const groups = groupByCategory(all);
    const total = [...groups.values()].reduce((n, g) => n + g.length, 0);
    assert.equal(total, all.length);
  });
});

describe('getLicenseTierInfoFrom — CHARIOT::§17.2::9 (rulings item 92)', () => {
  it('returns null tier/totalSeats when unlicensed', () => {
    const info = getLicenseTierInfoFrom({
      validateLicenseFn: () => ({ valid: false, mode: 'unlicensed' }),
      readLicenseEnvelopeFn: () => ({ jwt: 'unused', renewal_secret: 'x' }),
      decodeFn: () => ({ tier: 'chariot-25', totalSeats: 25 }),
    });
    assert.deepEqual(info, { mode: 'unlicensed', tier: null, totalSeats: null });
  });

  it('returns tier + totalSeats for a valid licensed JWT carrying both claims', () => {
    const info = getLicenseTierInfoFrom({
      validateLicenseFn: () => ({ valid: true, mode: 'licensed' }),
      readLicenseEnvelopeFn: () => ({ jwt: 'signed-jwt', renewal_secret: 'x' }),
      decodeFn: () => ({ tier: 'chariot-25', totalSeats: 25 }),
    });
    assert.deepEqual(info, { mode: 'licensed', tier: 'chariot-25', totalSeats: 25 });
  });

  it('returns tier with null totalSeats when the seats claim is absent (loader does not derive it from the tier name)', () => {
    const info = getLicenseTierInfoFrom({
      validateLicenseFn: () => ({ valid: true, mode: 'grace' }),
      readLicenseEnvelopeFn: () => ({ jwt: 'signed-jwt', renewal_secret: 'x' }),
      decodeFn: () => ({ tier: 'chariot-trial' }),
    });
    assert.deepEqual(info, { mode: 'grace', tier: 'chariot-trial', totalSeats: null });
  });

  it('returns null tier/totalSeats when valid=true but the envelope file is missing (race between validate and read)', () => {
    const info = getLicenseTierInfoFrom({
      validateLicenseFn: () => ({ valid: true, mode: 'licensed' }),
      readLicenseEnvelopeFn: () => null,
      decodeFn: () => ({ tier: 'chariot-25', totalSeats: 25 }),
    });
    assert.deepEqual(info, { mode: 'licensed', tier: null, totalSeats: null });
  });

  it('returns null tier/totalSeats when decodeFn returns null (signature/shape failure on re-decode)', () => {
    const info = getLicenseTierInfoFrom({
      validateLicenseFn: () => ({ valid: true, mode: 'licensed' }),
      readLicenseEnvelopeFn: () => ({ jwt: 'corrupt', renewal_secret: 'x' }),
      decodeFn: () => null,
    });
    assert.deepEqual(info, { mode: 'licensed', tier: null, totalSeats: null });
  });

  it('never throws — falls back to unlicensed when a dependency throws', () => {
    const info = getLicenseTierInfoFrom({
      validateLicenseFn: () => {
        throw new Error('fs error');
      },
      readLicenseEnvelopeFn: () => null,
      decodeFn: () => null,
    });
    assert.deepEqual(info, { mode: 'unlicensed', tier: null, totalSeats: null });
  });
});
