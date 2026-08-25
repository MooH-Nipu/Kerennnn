'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

function createSupabase() {
  const queries = [];
  const rangeCounts = { total: 4, malicious: 2, suspicious: 1, clean: 1 };
  const expectedFrom = '2026-08-25T00:00:00.000Z';
  const expectedTo = '2026-08-25T06:00:00.000Z';

  class Query {
    constructor(table) {
      this.table = table;
      this.filters = [];
      queries.push(this);
    }

    delete() { this.operation = 'delete'; return this; }
    select(columns, options) { this.columns = columns; this.options = options; return this; }
    eq(column, value) { this.filters.push(['eq', column, value]); return this; }
    gte(column, value) { this.filters.push(['gte', column, value]); return this; }
    lt(column, value) { this.filters.push(['lt', column, value]); return this; }
    order() { return this; }
    limit() { return this; }

    then(resolve, reject) {
      let result;
      if (this.operation === 'delete') result = { error: null };
      else if (this.options?.head) {
        const verdict = this.filters.find(([op, column]) => op === 'eq' && column === 'vt_verdict')?.[2] || 'total';
        const hasFrom = this.filters.some(([op, column, value]) => op === 'gte' && column === 'first_scanned_at' && value === expectedFrom);
        const hasTo = this.filters.some(([op, column, value]) => op === 'lt' && column === 'first_scanned_at' && value === expectedTo);
        result = { count: hasFrom && hasTo ? rangeCounts[verdict] : 999, error: null };
      } else result = { data: [], error: null };
      return Promise.resolve(result).then(resolve, reject);
    }
  }

  return {
    queries,
    from(table) { return new Query(table); },
  };
}

test('Dashboard cache summary counts follow selected time range', async () => {
  const supabase = createSupabase();
  const supabaseModule = require('./_supabase');
  const originalGetSupabase = supabaseModule.getSupabase;
  supabaseModule.getSupabase = () => supabase;
  delete require.cache[require.resolve('./ip-cache/recent')];
  const handler = require('./ip-cache/recent');
  supabaseModule.getSupabase = originalGetSupabase;

  const response = {
    statusCode: 200,
    payload: null,
    setHeader() {},
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };
  await handler({ method: 'GET', query: {
    limit: '50',
    from: '2026-08-25T00:00:00.000Z',
    to: '2026-08-25T06:00:00.000Z',
  } }, response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(
    {
      total: response.payload.total,
      malicious: response.payload.malicious,
      suspicious: response.payload.suspicious,
      clean: response.payload.clean,
    },
    { total: 4, malicious: 2, suspicious: 1, clean: 1 },
  );
  const countQueries = supabase.queries.filter(query => query.options?.head);
  assert.equal(countQueries.length, 4);
  for (const query of countQueries) {
    assert.ok(query.filters.some(filter => filter.join('|') === 'gte|first_scanned_at|2026-08-25T00:00:00.000Z'));
    assert.ok(query.filters.some(filter => filter.join('|') === 'lt|first_scanned_at|2026-08-25T06:00:00.000Z'));
  }
});
