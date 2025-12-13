// ========== 工具函数 ==========
function escapeHTML(input) {
  if (input === null || input === undefined) {
    return '';
  }
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\//g, '&#x2F;')
    .replace(/=/g, '&#x3D;');
}

function sanitizeUrl(url) {
  if (!url) {
    return '';
  }
  const trimmed = String(url).trim();
  
  if (/^javascript:/i.test(trimmed)) {
    return '';
  }
  
  try {
    const direct = new URL(trimmed);
    if (direct.protocol === 'http:' || direct.protocol === 'https:') {
      return direct.href;
    }
  } catch (error) {
    try {
      const fallback = new URL(`https://${trimmed}`);
      if (fallback.protocol === 'http:' || fallback.protocol === 'https:') {
        return fallback.href;
      }
    } catch (e) {
      return '';
    }
  }
  return '';
}

function normalizeSortOrder(value) {
  if (value === undefined || value === null || value === '') {
    return 9999;
  }
  const parsed = Number(value);
  if (Number.isFinite(parsed)) {
    const clamped = Math.max(-2147483648, Math.min(2147483647, Math.round(parsed)));
    return clamped;
  }
  return 9999;
}

function isSubmissionEnabled(env) {
  const flag = env.ENABLE_PUBLIC_SUBMISSION;
  if (flag === undefined || flag === null) {
    return true;
  }
  const normalized = String(flag).trim().toLowerCase();
  return normalized === 'true';
}

// ========== 会话管理 ==========
const SESSION_COOKIE_NAME = 'nav_admin_session';
const SESSION_PREFIX = 'session:';
const SESSION_TTL_SECONDS = 60 * 60 * 12;

function parseCookies(cookieHeader = '') {
  return cookieHeader
    .split(';')
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce((acc, pair) => {
      const separatorIndex = pair.indexOf('=');
      if (separatorIndex === -1) {
        acc[pair] = '';
      } else {
        const key = pair.slice(0, separatorIndex).trim();
        const value = pair.slice(separatorIndex + 1).trim();
        acc[key] = value;
      }
      return acc;
    }, {});
}

function buildSessionCookie(token, options = {}) {
  const { maxAge = SESSION_TTL_SECONDS } = options;
  const segments = [
    `${SESSION_COOKIE_NAME}=${token}`,
    'Path=/',
    `Max-Age=${maxAge}`,
    'HttpOnly',
    'SameSite=Strict',
    'Secure',
  ];
  return segments.join('; ');
}

async function createAdminSession(env) {
  const token = crypto.randomUUID();
  await env.NAV_AUTH.put(`${SESSION_PREFIX}${token}`, JSON.stringify({ createdAt: Date.now() }), {
    expirationTtl: SESSION_TTL_SECONDS,
  });
  return token;
}

async function refreshAdminSession(env, token, payload) {
  await env.NAV_AUTH.put(`${SESSION_PREFIX}${token}`, payload, { expirationTtl: SESSION_TTL_SECONDS });
}

async function destroyAdminSession(env, token) {
  if (!token) return;
  await env.NAV_AUTH.delete(`${SESSION_PREFIX}${token}`);
}

async function validateAdminSession(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const token = cookies[SESSION_COOKIE_NAME];
  if (!token) {
    return { authenticated: false };
  }
  const sessionKey = `${SESSION_PREFIX}${token}`;
  const payload = await env.NAV_AUTH.get(sessionKey);
  if (!payload) {
    return { authenticated: false };
  }
  await refreshAdminSession(env, token, payload);
  return { authenticated: true, token };
}

async function isAdminAuthenticated(request, env) {
  const { authenticated } = await validateAdminSession(request, env);
  return authenticated;
}

// ========== API处理 ==========
const api = {
  async handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace('/api', '');
    const method = request.method;
    const id = url.pathname.split('/').pop();

    try {
      if (path === '/config') {
        switch (method) {
          case 'GET':
            return await this.getConfig(request, env, ctx, url);
          case 'POST':
            if (!(await isAdminAuthenticated(request, env))) {
              return this.errorResponse('Unauthorized', 401);
            }
            return await this.createConfig(request, env, ctx);
          default:
            return this.errorResponse('Method Not Allowed', 405);
        }
      }
      
      if (path === '/config/submit' && method === 'POST') {
        if (!isSubmissionEnabled(env)) {
          return this.errorResponse('Public submission disabled', 403);
        }
        return await this.submitConfig(request, env, ctx);
      }
      
      if (path === '/categories' && method === 'GET') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.getCategories(request, env, ctx);
      }
      
      if (path.startsWith('/categories/')) {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        const categoryName = decodeURIComponent(path.replace('/categories/', ''));
        if (method === 'PUT') {
          return await this.updateCategoryOrder(request, env, ctx, categoryName);
        }
        return this.errorResponse('Method Not Allowed', 405);
      }
      
      if (path.startsWith('/config/') && /^\d+$/.test(id) && method === 'GET') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.getConfigById(request, env, ctx, id);
      }
      
      if (path === `/config/${id}` && /^\d+$/.test(id)) {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        switch (method) {
          case 'PUT':
            return await this.updateConfig(request, env, ctx, id);
          case 'DELETE':
            return await this.deleteConfig(request, env, ctx, id);
          default:
            return this.errorResponse('Method Not Allowed', 405);
        }
      }
      
      if (path.startsWith('/pending/') && /^\d+$/.test(id)) {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        switch (method) {
          case 'PUT':
            return await this.approvePendingConfig(request, env, ctx, id);
          case 'DELETE':
            return await this.rejectPendingConfig(request, env, ctx, id);
          default:
            return this.errorResponse('Method Not Allowed', 405);
        }
      }
      
      if (path === '/config/import' && method === 'POST') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.importConfig(request, env, ctx);
      }
      
      if (path === '/config/export' && method === 'GET') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.exportConfig(request, env, ctx);
      }
      
      if (path === '/pending' && method === 'GET') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.getPendingConfig(request, env, ctx, url);
      }
      
      if (path === '/init-db' && method === 'POST') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.initDatabase(request, env, ctx);
      }
      
      if (path === '/config/batch-update-order' && method === 'POST') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.batchUpdateOrder(request, env, ctx);
      }
      
      if (path === '/config/batch-update-tags' && method === 'POST') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.batchUpdateTags(request, env, ctx);
      }
      
      if (path === '/tags-group' && method === 'GET') {
        if (!(await isAdminAuthenticated(request, env))) {
          return this.errorResponse('Unauthorized', 401);
        }
        return await this.getTagsGroup(request, env, ctx);
      }
      
      return this.errorResponse('Not Found', 404);
    } catch (error) {
      return this.errorResponse(`Internal Server Error: ${error.message}`, 500);
    }
  },

  async getConfigById(request, env, ctx, id) {
    try {
      const { results } = await env.NAV_DB.prepare('SELECT * FROM sites WHERE id = ?').bind(id).all();
      if (results.length === 0) {
        return this.errorResponse('Config not found', 404);
      }
      return new Response(JSON.stringify({
        code: 200,
        data: results[0]
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return this.errorResponse(`Failed to fetch config: ${e.message}`, 500);
    }
  },

  async batchUpdateOrder(request, env, ctx) {
    try {
      const { items } = await request.json();
      if (!Array.isArray(items)) {
        return this.errorResponse('Invalid request format', 400);
      }
      
      const batchStatements = [];
      for (const item of items) {
        const { id, sort_order } = item;
        if (!id || sort_order === undefined) continue;
        const sortOrderValue = normalizeSortOrder(sort_order);
        batchStatements.push(
          env.NAV_DB.prepare(`UPDATE sites SET sort_order = ?, update_time = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(sortOrderValue, id)
        );
      }
      
      await env.NAV_DB.batch(batchStatements);
      
      return new Response(JSON.stringify({
        code: 200,
        message: '批量更新排序成功'
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
      return this.errorResponse(`批量更新排序失败: ${error.message}`, 500);
    }
  },

  async batchUpdateTags(request, env, ctx) {
    try {
      const { ids, tags, mode } = await request.json();
      if (!Array.isArray(ids) || typeof tags !== 'string') {
        return this.errorResponse('Invalid request format', 400);
      }
      
      const batchStatements = [];
      for (const id of ids) {
        let newTags = tags;
        
        if (mode === 'append') {
          const existing = await env.NAV_DB.prepare('SELECT tags FROM sites WHERE id = ?').bind(id).first();
          if (existing && existing.tags) {
            const existingTags = existing.tags.split(',').map(t => t.trim()).filter(t => t);
            const newTagsArray = tags.split(',').map(t => t.trim()).filter(t => t);
            const allTags = [...new Set([...existingTags, ...newTagsArray])];
            newTags = allTags.join(', ');
          }
        } else if (mode === 'remove') {
          const existing = await env.NAV_DB.prepare('SELECT tags FROM sites WHERE id = ?').bind(id).first();
          if (existing && existing.tags) {
            const existingTags = existing.tags.split(',').map(t => t.trim()).filter(t => t);
            const tagsToRemove = tags.split(',').map(t => t.trim()).filter(t => t);
            const remainingTags = existingTags.filter(t => !tagsToRemove.includes(t));
            newTags = remainingTags.join(', ');
          }
        }
        
        batchStatements.push(
          env.NAV_DB.prepare(`UPDATE sites SET tags = ?, update_time = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(newTags, id)
        );
      }
      
      await env.NAV_DB.batch(batchStatements);
      
      return new Response(JSON.stringify({
        code: 200,
        message: '批量更新标签成功'
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
      return this.errorResponse(`批量更新标签失败: ${error.message}`, 500);
    }
  },

  async getTagsGroup(request, env, ctx) {
    try {
      const { results } = await env.NAV_DB.prepare('SELECT * FROM sites ORDER BY sort_order ASC, create_time DESC').all();
      
      const tagsGroup = {};
      const untagged = [];
      
      results.forEach(site => {
        if (site.tags && site.tags.trim()) {
          const tags = site.tags.split(',').map(tag => tag.trim()).filter(tag => tag);
          tags.forEach(tag => {
            if (!tagsGroup[tag]) {
              tagsGroup[tag] = [];
            }
            tagsGroup[tag].push(site);
          });
        } else {
          untagged.push(site);
        }
      });
      
      const sortedTags = Object.keys(tagsGroup).sort();
      const result = {};
      
      sortedTags.forEach(tag => {
        result[tag] = tagsGroup[tag];
      });
      
      if (untagged.length > 0) {
        result['未分类'] = untagged;
      }
      
      return new Response(JSON.stringify({
        code: 200,
        data: result
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
      return this.errorResponse(`获取标签分组失败: ${error.message}`, 500);
    }
  },

  async initDatabase(request, env, ctx) {
    try {
      try {
        await env.NAV_DB.prepare(`ALTER TABLE sites ADD COLUMN tags TEXT`).run();
      } catch (e) {
        if (!e.message.includes('duplicate column name')) {
          console.error('Error adding tags column to sites table:', e);
        }
      }
      
      try {
        await env.NAV_DB.prepare(`ALTER TABLE pending_sites ADD COLUMN tags TEXT`).run();
      } catch (e) {
        if (!e.message.includes('duplicate column name')) {
          console.error('Error adding tags column to pending_sites table:', e);
        }
      }
      
      try {
        await env.NAV_DB.prepare(`CREATE TABLE IF NOT EXISTS category_orders (
          catelog TEXT PRIMARY KEY,
          sort_order INTEGER NOT NULL DEFAULT 9999
        )`).run();
      } catch (e) {
        console.error('Error creating category_orders table:', e);
      }
      
      return new Response(JSON.stringify({
        code: 200,
        message: 'Database initialized successfully'
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
      return this.errorResponse(`Failed to initialize database: ${error.message}`, 500);
    }
  },

  async getConfig(request, env, ctx, url) {
    const catalog = url.searchParams.get('catalog');
    const page = parseInt(url.searchParams.get('page') || '1', 10);
    const pageSize = parseInt(url.searchParams.get('pageSize') || '10', 10);
    const keyword = url.searchParams.get('keyword');
    const tag = url.searchParams.get('tag');
    const offset = (page - 1) * pageSize;
    
    try {
      let query = `SELECT * FROM sites ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
      let countQuery = `SELECT COUNT(*) as total FROM sites`;
      let queryBindParams = [pageSize, offset];
      let countQueryParams = [];

      if (catalog) {
        query = `SELECT * FROM sites WHERE catelog = ? ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
        countQuery = `SELECT COUNT(*) as total FROM sites WHERE catelog = ?`;
        queryBindParams = [catalog, pageSize, offset];
        countQueryParams = [catalog];
      }

      if (keyword) {
        const likeKeyword = `%${keyword}%`;
        query = `SELECT * FROM sites WHERE name LIKE ? OR url LIKE ? OR catelog LIKE ? ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
        countQuery = `SELECT COUNT(*) as total FROM sites WHERE name LIKE ? OR url LIKE ? OR catelog LIKE ?`;
        queryBindParams = [likeKeyword, likeKeyword, likeKeyword, pageSize, offset];
        countQueryParams = [likeKeyword, likeKeyword, likeKeyword];

        if (catalog) {
          query = `SELECT * FROM sites WHERE catelog = ? AND (name LIKE ? OR url LIKE ? OR catelog LIKE ?) ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
          countQuery = `SELECT COUNT(*) as total FROM sites WHERE catelog = ? AND (name LIKE ? OR url LIKE ? OR catelog LIKE ?)`;
          queryBindParams = [catalog, likeKeyword, likeKeyword, likeKeyword, pageSize, offset];
          countQueryParams = [catalog, likeKeyword, likeKeyword, likeKeyword];
        }
      }

      if (tag) {
        const likeTag = `%${tag}%`;
        if (keyword && catalog) {
          query = `SELECT * FROM sites WHERE catelog = ? AND (name LIKE ? OR url LIKE ? OR catelog LIKE ?) AND tags LIKE ? ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
          countQuery = `SELECT COUNT(*) as total FROM sites WHERE catelog = ? AND (name LIKE ? OR url LIKE ? OR catelog LIKE ?) AND tags LIKE ?`;
          queryBindParams = [catalog, likeKeyword, likeKeyword, likeKeyword, likeTag, pageSize, offset];
          countQueryParams = [catalog, likeKeyword, likeKeyword, likeKeyword, likeTag];
        } else if (keyword) {
          query = `SELECT * FROM sites WHERE (name LIKE ? OR url LIKE ? OR catelog LIKE ?) AND tags LIKE ? ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
          countQuery = `SELECT COUNT(*) as total FROM sites WHERE (name LIKE ? OR url LIKE ? OR catelog LIKE ?) AND tags LIKE ?`;
          queryBindParams = [likeKeyword, likeKeyword, likeKeyword, likeTag, pageSize, offset];
          countQueryParams = [likeKeyword, likeKeyword, likeKeyword, likeTag];
        } else if (catalog) {
          query = `SELECT * FROM sites WHERE catelog = ? AND tags LIKE ? ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
          countQuery = `SELECT COUNT(*) as total FROM sites WHERE catelog = ? AND tags LIKE ?`;
          queryBindParams = [catalog, likeTag, pageSize, offset];
          countQueryParams = [catalog, likeTag];
        } else {
          query = `SELECT * FROM sites WHERE tags LIKE ? ORDER BY sort_order ASC, create_time DESC LIMIT ? OFFSET ?`;
          countQuery = `SELECT COUNT(*) as total FROM sites WHERE tags LIKE ?`;
          queryBindParams = [likeTag, pageSize, offset];
          countQueryParams = [likeTag];
        }
      }

      const { results } = await env.NAV_DB.prepare(query).bind(...queryBindParams).all();
      const countResult = await env.NAV_DB.prepare(countQuery).bind(...countQueryParams).first();
      const total = countResult ? countResult.total : 0;

      return new Response(
        JSON.stringify({
          code: 200,
          data: results,
          total,
          page,
          pageSize
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    } catch (e) {
      return this.errorResponse(`Failed to fetch config data: ${e.message}`, 500);
    }
  },

  async getPendingConfig(request, env, ctx, url) {
    const page = parseInt(url.searchParams.get('page') || '1', 10);
    const pageSize = parseInt(url.searchParams.get('pageSize') || '10', 10);
    const offset = (page - 1) * pageSize;
    
    try {
      const { results } = await env.NAV_DB.prepare(`
        SELECT * FROM pending_sites ORDER BY create_time DESC LIMIT ? OFFSET ?
      `).bind(pageSize, offset).all();
      
      const countResult = await env.NAV_DB.prepare(`
        SELECT COUNT(*) as total FROM pending_sites
      `).first();
      
      const total = countResult ? countResult.total : 0;
      
      return new Response(
        JSON.stringify({
          code: 200,
          data: results,
          total,
          page,
          pageSize
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    } catch (e) {
      return this.errorResponse(`Failed to fetch pending config data: ${e.message}`, 500);
    }
  },

  async approvePendingConfig(request, env, ctx, id) {
    try {
      const { results } = await env.NAV_DB.prepare('SELECT * FROM pending_sites WHERE id = ?').bind(id).all();
      if (results.length === 0) {
        return this.errorResponse('Pending config not found', 404);
      }
      const config = results[0];
      
      await env.NAV_DB.prepare(`
        INSERT INTO sites (name, url, logo, desc, catelog, sort_order, tags)
        VALUES (?, ?, ?, ?, ?, 9999, ?) 
      `).bind(config.name, config.url, config.logo, config.desc, config.catelog, config.tags || '').run();
      
      await env.NAV_DB.prepare('DELETE FROM pending_sites WHERE id = ?').bind(id).run();

      return new Response(JSON.stringify({
        code: 200,
        message: 'Pending config approved successfully'
      }), {
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (e) {
      return this.errorResponse(`Failed to approve pending config: ${e.message}`, 500);
    }
  },

  async rejectPendingConfig(request, env, ctx, id) {
    try {
      await env.NAV_DB.prepare('DELETE FROM pending_sites WHERE id = ?').bind(id).run();
      return new Response(JSON.stringify({
        code: 200,
        message: 'Pending config rejected successfully',
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return this.errorResponse(`Failed to reject pending config: ${e.message}`, 500);
    }
  },

  async submitConfig(request, env, ctx) {
    try {
      if (!isSubmissionEnabled(env)) {
        return this.errorResponse('Public submission disabled', 403);
      }
      
      const config = await request.json();
      const { name, url, logo, desc, catelog, tags } = config;
      const sanitizedName = (name || '').trim();
      const sanitizedUrl = (url || '').trim();
      const sanitizedCatelog = (catelog || '').trim();
      const sanitizedLogo = (logo || '').trim() || null;
      const sanitizedDesc = (desc || '').trim() || null;
      const sanitizedTags = (tags || '').trim() || null;

      if (!sanitizedName || !sanitizedUrl || !sanitizedCatelog) {
        return this.errorResponse('Name, URL and Catelog are required', 400);
      }
      
      await env.NAV_DB.prepare(`
        INSERT INTO pending_sites (name, url, logo, desc, catelog, tags)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(sanitizedName, sanitizedUrl, sanitizedLogo, sanitizedDesc, sanitizedCatelog, sanitizedTags).run();

      return new Response(JSON.stringify({
        code: 201,
        message: 'Config submitted successfully, waiting for admin approve',
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (e) {
      return this.errorResponse(`Failed to submit config: ${e.message}`, 500);
    }
  },

  async createConfig(request, env, ctx) {
    try {
      const config = await request.json();
      const { name, url, logo, desc, catelog, sort_order, tags } = config;
      const sanitizedName = (name || '').trim();
      const sanitizedUrl = (url || '').trim();
      const sanitizedCatelog = (catelog || '').trim();
      const sanitizedLogo = (logo || '').trim() || null;
      const sanitizedDesc = (desc || '').trim() || null;
      const sanitizedTags = (tags || '').trim() || null;
      const sortOrderValue = normalizeSortOrder(sort_order);

      if (!sanitizedName || !sanitizedUrl || !sanitizedCatelog) {
        return this.errorResponse('Name, URL and Catelog are required', 400);
      }
      
      const insert = await env.NAV_DB.prepare(`
        INSERT INTO sites (name, url, logo, desc, catelog, sort_order, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(sanitizedName, sanitizedUrl, sanitizedLogo, sanitizedDesc, sanitizedCatelog, sortOrderValue, sanitizedTags).run();

      return new Response(JSON.stringify({
        code: 201,
        message: 'Config created successfully',
        insert
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (e) {
      return this.errorResponse(`Failed to create config: ${e.message}`, 500);
    }
  },

  async updateConfig(request, env, ctx, id) {
    try {
      const config = await request.json();
      const { name, url, logo, desc, catelog, sort_order, tags } = config;
      const sanitizedName = (name || '').trim();
      const sanitizedUrl = (url || '').trim();
      const sanitizedCatelog = (catelog || '').trim();
      const sanitizedLogo = (logo || '').trim() || null;
      const sanitizedDesc = (desc || '').trim() || null;
      const sanitizedTags = (tags || '').trim() || null;
      const sortOrderValue = normalizeSortOrder(sort_order);

      if (!sanitizedName || !sanitizedUrl || !sanitizedCatelog) {
        return this.errorResponse('Name, URL and Catelog are required', 400);
      }
      
      const update = await env.NAV_DB.prepare(`
        UPDATE sites
        SET name = ?, url = ?, logo = ?, desc = ?, catelog = ?, sort_order = ?, tags = ?, update_time = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(sanitizedName, sanitizedUrl, sanitizedLogo, sanitizedDesc, sanitizedCatelog, sortOrderValue, sanitizedTags, id).run();
      
      return new Response(JSON.stringify({
        code: 200,
        message: 'Config updated successfully',
        update
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return this.errorResponse(`Failed to update config: ${e.message}`, 500);
    }
  },

  async deleteConfig(request, env, ctx, id) {
    try {
      const del = await env.NAV_DB.prepare('DELETE FROM sites WHERE id = ?').bind(id).run();
      return new Response(JSON.stringify({
        code: 200,
        message: 'Config deleted successfully',
        del
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return this.errorResponse(`Failed to delete config: ${e.message}`, 500);
    }
  },

  async importConfig(request, env, ctx) {
    try {
      const jsonData = await request.json();
      let sitesToImport = [];

      if (Array.isArray(jsonData)) {
        sitesToImport = jsonData;
      } else if (jsonData && typeof jsonData === 'object' && Array.isArray(jsonData.data)) {
        sitesToImport = jsonData.data;
      } else {
        return this.errorResponse('Invalid JSON data. Must be an array of site configurations, or an object with a "data" key containing array.', 400);
      }

      if (sitesToImport.length === 0) {
        return new Response(JSON.stringify({
          code: 200,
          message: 'Import successful, but no data was found in the file.'
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      const insertStatements = sitesToImport.map(item => {
        const sanitizedName = (item.name || '').trim() || null;
        const sanitizedUrl = (item.url || '').trim() || null;
        const sanitizedLogo = (item.logo || '').trim() || null;
        const sanitizedDesc = (item.desc || '').trim() || null;
        const sanitizedCatelog = (item.catelog || '').trim() || null;
        const sanitizedTags = (item.tags || '').trim() || null;
        const sortOrderValue = normalizeSortOrder(item.sort_order);
        return env.NAV_DB.prepare(`
          INSERT INTO sites (name, url, logo, desc, catelog, sort_order, tags)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(sanitizedName, sanitizedUrl, sanitizedLogo, sanitizedDesc, sanitizedCatelog, sortOrderValue, sanitizedTags);
      });

      await env.NAV_DB.batch(insertStatements);

      return new Response(JSON.stringify({
        code: 201,
        message: `Config imported successfully. ${sitesToImport.length} items added.`
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return this.errorResponse(`Failed to import config: ${error.message}`, 500);
    }
  },

  async exportConfig(request, env, ctx) {
    try {
      const { results } = await env.NAV_DB.prepare('SELECT * FROM sites ORDER BY sort_order ASC, create_time DESC').all();
      const pureJsonData = JSON.stringify(results, null, 2);

      return new Response(pureJsonData, {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': 'attachment; filename="config.json"'
        }
      });
    } catch (e) {
      return this.errorResponse(`Failed to export config: ${e.message}`, 500);
    }
  },

  async getCategories(request, env, ctx) {
    try {
      const categoryOrderMap = new Map();
      try {
        const { results: orderRows } = await env.NAV_DB.prepare('SELECT catelog, sort_order FROM category_orders').all();
        orderRows.forEach(row => {
          categoryOrderMap.set(row.catelog, normalizeSortOrder(row.sort_order));
        });
      } catch (error) {
        if (!/no such table/i.test(error.message || '')) {
          throw error;
        }
      }

      const { results } = await env.NAV_DB.prepare(`
        SELECT catelog, COUNT(*) AS site_count, MIN(sort_order) AS min_site_sort
        FROM sites
        GROUP BY catelog
      `).all();

      const data = results.map(row => ({
        catelog: row.catelog,
        site_count: row.site_count,
        sort_order: categoryOrderMap.has(row.catelog)
          ? categoryOrderMap.get(row.catelog)
          : normalizeSortOrder(row.min_site_sort),
        explicit: categoryOrderMap.has(row.catelog),
        min_site_sort: row.min_site_sort === null ? 9999 : normalizeSortOrder(row.min_site_sort)
      }));

      data.sort((a, b) => {
        if (a.sort_order !== b.sort_order) {
          return a.sort_order - b.sort_order;
        }
        if (a.min_site_sort !== b.min_site_sort) {
          return a.min_site_sort - b.min_site_sort;
        }
        return a.catelog.localeCompare(b.catelog, 'zh-Hans-CN', { sensitivity: 'base' });
      });

      return new Response(JSON.stringify({
        code: 200,
        data
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return this.errorResponse(`Failed to fetch categories: ${e.message}`, 500);
    }
  },

  async updateCategoryOrder(request, env, ctx, categoryName) {
    try {
      const body = await request.json();
      if (!categoryName) {
        return this.errorResponse('Category name is required', 400);
      }

      const normalizedCategory = categoryName.trim();
      if (!normalizedCategory) {
        return this.errorResponse('Category name is required', 400);
      }

      try {
        await env.NAV_DB.prepare(`CREATE TABLE IF NOT EXISTS category_orders (
          catelog TEXT PRIMARY KEY,
          sort_order INTEGER NOT NULL DEFAULT 9999
        )`).run();
      } catch (e) {
        console.error('Error ensuring category_orders table exists:', e);
      }

      if (body && body.reset) {
        await env.NAV_DB.prepare('DELETE FROM category_orders WHERE catelog = ?')
          .bind(normalizedCategory)
          .run();
        return new Response(JSON.stringify({
          code: 200,
          message: 'Category order reset successfully'
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      const sortOrderValue = normalizeSortOrder(body ? body.sort_order : undefined);
      
      await env.NAV_DB.prepare(`
        INSERT OR REPLACE INTO category_orders (catelog, sort_order)
        VALUES (?, ?)
      `).bind(normalizedCategory, sortOrderValue).run();

      return new Response(JSON.stringify({
        code: 200,
        message: 'Category order updated successfully',
        sort_order: sortOrderValue
      }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return this.errorResponse(`Failed to update category order: ${e.message}`, 500);
    }
  },

  errorResponse(message, status) {
    return new Response(JSON.stringify({ code: status, message: message }), {
      status: status,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

// ========== 后台管理 ==========
const admin = {
  async handleRequest(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/admin/logout') {
      if (request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
      }
      const { token } = await validateAdminSession(request, env);
      if (token) {
        await destroyAdminSession(env, token);
      }
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/admin',
          'Set-Cookie': buildSessionCookie('', { maxAge: 0 }),
        },
      });
    }

    if (url.pathname === '/admin') {
      if (request.method === 'POST') {
        const formData = await request.formData();
        const name = (formData.get('name') || '').trim();
        const password = (formData.get('password') || '').trim();

        const storedUsername = await env.NAV_AUTH.get('admin_username');
        const storedPassword = await env.NAV_AUTH.get('admin_password');

        const isValid =
          storedUsername &&
          storedPassword &&
          name === storedUsername &&
          password === storedPassword;

        if (isValid) {
          const token = await createAdminSession(env);
          return new Response(null, {
            status: 302,
            headers: {
              Location: '/admin',
              'Set-Cookie': buildSessionCookie(token),
            },
          });
        }

        return this.renderLoginPage('账号或密码错误，请重试。');
      }

      const session = await validateAdminSession(request, env);
      if (session.authenticated) {
        return this.renderAdminPage();
      }

      return this.renderLoginPage();
    }

    if (url.pathname.startsWith('/static')) {
      return this.handleStatic(request, env, ctx);
    }

    return new Response('页面不存在', { status: 404 });
  },

  async handleStatic(request, env, ctx) {
    const url = new URL(request.url);
    const filePath = url.pathname.replace('/static/', '');

    let contentType = 'text/plain';
    if (filePath.endsWith('.css')) {
      contentType = 'text/css';
    } else if (filePath.endsWith('.js')) {
      contentType = 'application/javascript';
    }

    try {
      const fileContent = await this.getFileContent(filePath);
      return new Response(fileContent, {
        headers: { 'Content-Type': contentType }
      });
    } catch (e) {
      return new Response('Not Found', { status: 404 });
    }
  },

  async getFileContent(filePath) {
    const fileContents = {
      'admin.html': `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>书签管理页面</title>
  <link rel="stylesheet" href="/static/admin.css">
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.js"></script>
</head>
<body>
  <div class="container">
      <header class="admin-header">
        <div>
          <h1>书签管理</h1>
          <p class="admin-subtitle">管理后台仅限受信任的管理员使用，请妥善保管账号</p>
        </div>
        <form method="post" action="/admin/logout">
          <button type="submit" class="logout-btn">退出登录</button>
        </form>
      </header>

      <div class="import-export">
        <input type="file" id="importFile" accept=".json" style="display:none;">
        <button id="importBtn">导入</button>
        <button id="exportBtn">导出</button>
        <button id="initDbBtn">初始化数据库</button>
      </div>

      <div class="add-new">
        <input type="text" id="addName" placeholder="Name" required>
        <input type="text" id="addUrl" placeholder="URL" required>
        <input type="text" id="addLogo" placeholder="Logo(optional)">
        <input type="text" id="addDesc" placeholder="Description(optional)">
        <input type="text" id="addCatelog" placeholder="Catelog" required list="catalogList">
        <input type="text" id="addTags" placeholder="Tags(comma separated)">
        <input type="number" id="addSortOrder" placeholder="排序 (数字小靠前)">
        <button id="addBtn">添加</button>
      </div>
      <div id="message" style="display: none;padding:1rem;border-radius: 0.5rem;margin-bottom: 1rem;"></div>
     <div class="tab-wrapper">
          <div class="tab-buttons">
             <button class="tab-button active" data-tab="categories">分类管理</button>
             <button class="tab-button" data-tab="pending">待审核列表</button>
          </div>
           <div id="categories" class="tab-content active">
                <div class="table-wrapper">
                    <div class="category-toolbar">
                        <p class="category-hint">点击分类名称展开/折叠书签，拖拽书签可调整排序。点击编辑图标可重命名分类。设置分类排序值（数字越小越靠前），留空表示使用默认顺序。</p>
                        <button id="refreshCategories" type="button">刷新</button>
                    </div>
                    <div class="batch-actions">
                        <button id="saveOrderBtn" class="batch-btn" style="display:none;">保存排序</button>
                    </div>
                    <table id="categoryTable">
                        <thead>
                            <tr>
                                <th colspan="2">分类</th>
                                <th>排序值</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="categoryTableBody">
                            <tr><td colspan="4">加载中...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
           <div id="pending" class="tab-content">
             <div class="table-wrapper">
               <table id="pendingTable">
                  <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>URL</th>
                        <th>Logo</th>
                        <th>Description</th>
                        <th>Catelog</th>
                        <th>Tags</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody id="pendingTableBody">
                       <!-- data render by js -->
                    </tbody>
                </table>
                <div class="pagination">
                  <button id="pendingPrevPage" disabled>上一页</button>
                   <span id="pendingCurrentPage">1</span>/<span id="pendingTotalPages">1</span>
                  <button id="pendingNextPage" disabled>下一页</button>
                </div>
           </div>
          </div>
      </div>
  </div>
  <script src="/static/admin.js"></script>
</body>
</html>`,

      'admin.css': `body {
  font-family: 'Noto Sans SC', sans-serif;
  margin: 0;
  padding: 10px;
  background-color: #f8f9fa;
  color: #212529;
}
.modal {
  display: none;
  position: fixed;
  z-index: 1000;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  overflow: auto;
  background-color: rgba(0, 0, 0, 0.5);
}
.modal-content {
  background-color: #fff;
  margin: 10% auto;
  padding: 20px;
  border: 1px solid #dee2e6;
  width: 80%;
  max-width: 600px;
  border-radius: 8px;
  position: relative;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}
.modal-close {
  color: #6c757d;
  position: absolute;
  right: 10px;
  top: 0;
  font-size: 28px;
  font-weight: bold;
  cursor: pointer;
  transition: color 0.2s;
}
.modal-close:hover,
.modal-close:focus {
  color: #343a40;
  text-decoration: none;
  cursor: pointer;
}
.modal-content form {
  display: flex;
  flex-direction: column;
}
.modal-content form label {
  margin-bottom: 5px;
  font-weight: 500;
  color: #495057;
}
.modal-content form input {
  margin-bottom: 10px;
  padding: 10px;
  border: 1px solid #ced4da;
  border-radius: 4px;
  font-size: 1rem;
  outline: none;
  transition: border-color 0.2s;
}
.modal-content form input:focus {
  border-color: #80bdff;
  box-shadow:0 0 0 0.2rem rgba(0,123,255,.25);
}
.modal-content button[type='submit'] {
  margin-top: 10px;
  background-color: #007bff;
  color: #fff;
  border: none;
  padding: 10px 15px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  transition: background-color 0.3s;
}
.modal-content button[type='submit']:hover {
  background-color: #0056b3;
}
.form-group {
  margin-bottom: 15px;
}
.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 20px;
}
.radio-group {
  display: flex;
  gap: 15px;
  margin-top: 5px;
}
.radio-group label {
  display: flex;
  align-items: center;
  gap: 5px;
  font-weight: normal;
}
.btn-primary, .btn-secondary {
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  border: none;
  transition: background-color 0.2s;
}
.btn-primary {
  background-color: #007bff;
  color: white;
}
.btn-primary:hover {
  background-color: #0069d9;
}
.btn-secondary {
  background-color: #6c757d;
  color: white;
}
.btn-secondary:hover {
  background-color: #5a6268;
}
.container {
  max-width: 1200px;
  margin: 0 auto;
  background-color: #fff;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}
.admin-header {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 24px;
}
@media (min-width: 768px) {
  .admin-header {
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
  }
}
h1 {
  font-size: 1.75rem;
  margin: 0;
  color: #343a40;
}
.admin-subtitle {
  margin: 4px 0 0;
  color: #6c757d;
  font-size: 0.95rem;
}
.logout-btn {
  background-color: #f8f9fa;
  color: #495057;
  border: 1px solid #ced4da;
  padding: 8px 14px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.95rem;
  transition: background-color 0.2s, color 0.2s, box-shadow 0.2s;
}
.logout-btn:hover {
  background-color: #e9ecef;
  color: #212529;
  box-shadow: 0 3px 10px rgba(0,0,0,0.08);
}
.tab-wrapper {
  margin-top: 20px;
}
.tab-buttons {
  display: flex;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.tab-button {
  background-color: #e9ecef;
  border: 1px solid #dee2e6;
  padding: 10px 15px;
  border-radius: 4px 4px 0 0;
  cursor: pointer;
  color: #495057;
  transition: background-color 0.2s, color 0.2s;
}
.tab-button.active {
  background-color: #fff;
  border-bottom: 1px solid #fff;
  color: #212529;
}
.tab-button:hover {
  background-color: #f0f0f0;
}
.tab-content {
  display: none;
  border: 1px solid #dee2e6;
  padding: 10px;
  border-top: none;
}
.tab-content.active {
  display: block;
}
.import-export {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  justify-content: flex-end;
  flex-wrap: wrap;
}
.add-new {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}
.add-new > input {
  flex: 1 1 150px;
  min-width: 150px;
}
.add-new > button {
  flex-basis: 100%;
}
input[type="text"], input[type="number"] {
  padding: 10px;
  border: 1px solid #ced4da;
  border-radius: 4px;
  font-size: 1rem;
  outline: none;
  margin-bottom: 5px;
  transition: border-color 0.2s;
}
@media (min-width: 768px) {
  .add-new > button {
    flex-basis: auto;
  }
}
input[type="text"]:focus, input[type="number"]:focus {
  border-color: #80bdff;
  box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
}
button {
  background-color: #6c63ff;
  color: #fff;
  border: none;
  padding: 10px 15px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  transition: background-color 0.3s;
}
button:hover {
  background-color: #534dc4;
}
.table-wrapper {
  overflow-x: auto;
}
table {
  width: 100%;
  min-width: 900px;
  border-collapse: collapse;
  margin-bottom: 20px;
}
th, td {
  border: 1px solid #dee2e6;
  padding: 10px;
  text-align: left;
  color: #495057;
}
th {
  background-color: #f2f2f2;
  font-weight: 600;
}
tr:nth-child(even) {
  background-color: #f9f9f9;
}
.batch-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 15px;
  flex-wrap: wrap;
}
.batch-btn {
  padding: 6px 12px;
  background-color: #17a2b8;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: background-color 0.2s;
}
.batch-btn:hover {
  background-color: #138496;
}
.category-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  gap: 10px;
  flex-wrap: wrap;
}
.category-hint {
  margin: 0;
  font-size: 0.85rem;
  color: #6c757d;
}
#refreshCategories {
  background-color: #f8f9fa;
  color: #495057;
  border: 1px solid #ced4da;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: background-color 0.2s;
}
#refreshCategories:hover {
  background-color: #e9ecef;
}
.category-sort-input {
  width: 80px;
  padding: 6px 8px;
  border: 1px solid #ced4da;
  border-radius: 4px;
  text-align: center;
}
.category-sort-input:focus {
  border-color: #80bdff;
  box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
  outline: none;
}
.category-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.category-actions button {
  padding: 5px 10px;
  font-size: 0.85rem;
  transition: background-color 0.2s;
}
.category-actions button:hover {
  opacity: 0.8;
}
.category-actions button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.actions {
  display: flex;
  gap: 5px;
}
.actions button {
  padding: 5px 8px;
  font-size: 0.8rem;
}
.edit-btn {
  background-color: #17a2b8;
}
.del-btn {
  background-color: #dc3545;
}
.pagination {
  text-align: center;
  margin-top: 20px;
}
.pagination button {
  margin: 0 5px;
  background-color: #e9ecef;
  color: #495057;
  border: 1px solid #ced4da;
}
.pagination button:hover {
  background-color: #dee2e6;
}
.success {
  background-color: #28a745;
  color: #fff;
}
.error {
  background-color: #dc3545;
  color: #fff;
}
.category-header {
  display: flex;
  align-items: center;
  cursor: pointer;
  padding: 8px 0;
}
.expand-icon {
  margin-right: 8px;
  transition: transform 0.2s;
}
.category-name {
  font-weight: 600;
  color: #495057;
  cursor: pointer;
  position: relative;
}
.category-name:hover::after {
  content: "双击重命名";
  position: absolute;
  top: -20px;
  left: 0;
  background: rgba(0, 0, 0, 0.7);
  color: white;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
  white-space: nowrap;
  z-index: 10;
}
.site-count {
  margin-left: 8px;
  color: #6c757d;
  font-size: 0.85rem;
}
.sites-container {
  background-color: #f8f9fa;
}
.sites-list {
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.site-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background-color: white;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  cursor: move;
}
.site-info {
  flex: 1;
}
.site-name {
  font-weight: 500;
  color: #212529;
}
.site-url {
  font-size: 0.85rem;
  color: #6c757d;
  word-break: break-all;
}
.site-actions {
  display: flex;
  gap: 5px;
}
.sortable-ghost {
  opacity: 0.4;
  background-color: #f0f8ff;
}
.sortable-drag {
  opacity: 0.9;
}
.category-name-input {
  background: transparent;
  border: 1px solid #416d9d;
  border-radius: 4px;
  padding: 2px 6px;
  font-size: inherit;
  font-weight: inherit;
  color: inherit;
  width: 100%;
  outline: none;
}
.category-edit-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  margin-left: 8px;
  color: #007bff;
  transition: color 0.2s, transform 0.2s;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 4px;
}
.category-edit-btn:hover {
  color: #0056b3;
  background-color: rgba(0, 123, 255, 0.1);
  transform: scale(1.1);
}
.category-edit-btn svg {
  width: 16px;
  height: 16px;
}`,

      'admin.js': `// 全局变量
const categoryTableBody = document.getElementById('categoryTableBody');
const refreshCategoriesBtn = document.getElementById('refreshCategories');
const initDbBtn = document.getElementById('initDbBtn');
const saveOrderBtn = document.getElementById('saveOrderBtn');

const pendingTableBody = document.getElementById('pendingTableBody');
const pendingPrevPageBtn = document.getElementById('pendingPrevPage');
const pendingNextPageBtn = document.getElementById('pendingNextPage');
const pendingCurrentPageSpan = document.getElementById('pendingCurrentPage');
const pendingTotalPagesSpan = document.getElementById('pendingTotalPages');

const messageDiv = document.getElementById('message');

const batchTagsModal = document.getElementById('batchTagsModal');
const batchTagsForm = document.getElementById('batchTagsForm');
const batchTagsInput = document.getElementById('batchTagsInput');
const cancelBatchTags = document.getElementById('cancelBatchTags');

let categoriesData = new Map();
let sitesData = [];

// 工具函数
var escapeHTML = function(value) {
  var result = '';
  if (value !== null && value !== undefined) {
    result = String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  return result;
};

var normalizeUrl = function(value) {
  var trimmed = String(value || '').trim();
  var normalized = '';
  if (/^https?:\\/\\//i.test(trimmed)) {
    normalized = trimmed;
  } else if (/^[\\w.-]+\\.[\\w.-]+/.test(trimmed)) {
    normalized = 'https://' + trimmed;
  }
  return normalized;
};

function normalizeSortOrder(value) {
  if (value === undefined || value === null || value === '') {
    return 9999;
  }
  const parsed = Number(value);
  if (Number.isFinite(parsed)) {
    const clamped = Math.max(-2147483648, Math.min(2147483647, Math.round(parsed)));
    return clamped;
  }
  return 9999;
}

// DOM元素
const addBtn = document.getElementById('addBtn');
const addName = document.getElementById('addName');
const addUrl = document.getElementById('addUrl');
const addLogo = document.getElementById('addLogo');
const addDesc = document.getElementById('addDesc');
const addCatelog = document.getElementById('addCatelog');
const addTags = document.getElementById('addTags');
const addSortOrder = document.getElementById('addSortOrder');

const importBtn = document.getElementById('importBtn');
const importFile = document.getElementById('importFile');
const exportBtn = document.getElementById('exportBtn');

const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');

// 标签页切换
tabButtons.forEach(button => {
  button.addEventListener('click', () => {
    const tab = button.dataset.tab;
    tabButtons.forEach(b => b.classList.remove('active'));
    button.classList.add('active');
    tabContents.forEach(content => {
      content.classList.remove('active');
      if(content.id === tab) {
        content.classList.add('active');
      }
    });
    if (tab === 'categories') {
      fetchCategoriesWithSites();
    }
  });
});

// 刷新分类
if (refreshCategoriesBtn) {
  refreshCategoriesBtn.addEventListener('click', () => {
    fetchCategoriesWithSites();
  });
}

// 初始化数据库
if (initDbBtn) {
  initDbBtn.addEventListener('click', async () => {
    try {
      const response = await fetch('/api/init-db', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      if (data.code === 200) {
        showMessage('数据库初始化成功', 'success');
        fetchCategoriesWithSites();
      } else {
        showMessage(data.message || '初始化失败', 'error');
      }
    } catch (err) {
      showMessage('网络错误', 'error');
    }
  });
}

// 待审核分页
let pendingCurrentPage = 1;
let pendingPageSize = 10;
let pendingTotalItems = 0;
let allPendingConfigs = [];

// 编辑模态框
const editModal = document.createElement('div');
editModal.className = 'modal';
editModal.style.display = 'none';
editModal.innerHTML = \`
  <div class="modal-content">
    <span class="modal-close">&times;</span>
    <h2>编辑站点</h2>
    <form id="editForm">
      <input type="hidden" id="editId">
      <label for="editName">名称:</label>
      <input type="text" id="editName" required><br>
      <label for="editUrl">URL:</label>
      <input type="text" id="editUrl" required><br>
      <label for="editLogo">Logo(可选):</label>
      <input type="text" id="editLogo"><br>
      <label for="editDesc">描述(可选):</label>
      <input type="text" id="editDesc"><br>
      <label for="editCatelog">分类:</label>
      <input type="text" id="editCatelog" required list="editCatalogList"><br>
      <label for="editTags">标签(逗号分隔):</label>
      <input type="text" id="editTags"><br>
      <label for="editSortOrder">排序:</label>
      <input type="number" id="editSortOrder"><br>
      <button type="submit">保存</button>
    </form>
  </div>
\`;
document.body.appendChild(editModal);

const modalClose = editModal.querySelector('.modal-close');
modalClose.addEventListener('click', () => {
  editModal.style.display = 'none';
});

const editForm = document.getElementById('editForm');
editForm.addEventListener('submit', function (e) {
  e.preventDefault();
  const id = document.getElementById('editId').value;
  const name = document.getElementById('editName').value;
  const url = document.getElementById('editUrl').value;
  const logo = document.getElementById('editLogo').value;
  const desc = document.getElementById('editDesc').value;
  const catelog = document.getElementById('editCatelog').value;
  const tags = document.getElementById('editTags').value;
  const sort_order = document.getElementById('editSortOrder').value;
  const payload = {
      name: name.trim(),
      url: url.trim(),
      logo: logo.trim(),
      desc: desc.trim(),
      catelog: catelog.trim(),
      tags: tags.trim()
  };
  if (sort_order !== '') {
      payload.sort_order = Number(sort_order);
  }
  fetch(\`/api/config/\${id}\`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  }).then(res => res.json())
    .then(data => {
      if (data.code === 200) {
        showMessage('修改成功', 'success');
        fetchCategoriesWithSites();
        editModal.style.display = 'none';
      } else {
        showMessage(data.message, 'error');
      }
    }).catch(err => {
      showMessage('网络错误', 'error');
    })
});

// 保存排序
saveOrderBtn.addEventListener('click', async () => {
  const allSitesLists = document.querySelectorAll('.sites-list');
  const items = [];
  
  allSitesLists.forEach(list => {
      const siteItems = list.querySelectorAll('.site-item');
      siteItems.forEach((item, index) => {
          const id = item.getAttribute('data-id');
          if (id) {
              items.push({
                  id: id,
                  sort_order: index * 10
              });
          }
      });
  });
  
  try {
      const response = await fetch('/api/config/batch-update-order', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json'
          },
          body: JSON.stringify({ items })
      });
      
      const data = await response.json();
      if (data.code === 200) {
          showMessage('排序保存成功', 'success');
          saveOrderBtn.style.display = 'none';
          fetchCategoriesWithSites();
      } else {
          showMessage(data.message || '保存失败', 'error');
      }
  } catch (err) {
      showMessage('网络错误', 'error');
  }
});

// 获取分类和站点
async function fetchCategoriesWithSites() {
  if (!categoryTableBody) {
      return;
  }
  categoryTableBody.innerHTML = '<tr><td colspan="4">加载中...</td></tr>';
  
  try {
      const categoryOrderMap = new Map();
      try {
          const response = await fetch('/api/categories');
          const data = await response.json();
          if (data.code === 200) {
              const orderRows = data.data || [];
              orderRows.forEach(row => {
                  categoryOrderMap.set(row.catelog, normalizeSortOrder(row.sort_order));
              });
          }
      } catch (error) {
          console.error('获取分类排序失败:', error);
      }
      
      let sites = [];
      try {
          const response = await fetch('/api/config?page=1&pageSize=1000');
          const data = await response.json();
          if (data.code === 200) {
              sites = data.data || [];
              sitesData = sites;
          }
      } catch (error) {
          console.error('获取书签失败:', error);
      }
      
      const categoryMap = new Map();
      sites.forEach(site => {
          const categoryName = (site.catelog || '').trim() || '未分类';
          if (!categoryMap.has(categoryName)) {
              categoryMap.set(categoryName, []);
          }
          categoryMap.get(categoryName).push(site);
      });
      
      const sortedCategories = Array.from(categoryMap.keys()).sort((a, b) => {
          const orderA = categoryOrderMap.has(a) ? categoryOrderMap.get(a) : 9999;
          const orderB = categoryOrderMap.has(b) ? categoryOrderMap.get(b) : 9999;
          if (orderA !== orderB) return orderA - orderB;
          return a.localeCompare(b, 'zh-Hans-CN', { sensitivity: 'base' });
      });
      
      categoriesData = categoryMap;
      
      renderCategoriesWithSites(sortedCategories, categoryMap, categoryOrderMap);
  } catch (error) {
      console.error('获取数据失败:', error);
      showMessage('获取数据失败', 'error');
      categoryTableBody.innerHTML = '<tr><td colspan="4">加载失败</td></tr>';
  }
}

// 渲染分类和站点
function renderCategoriesWithSites(categories, categoryMap, categoryOrderMap) {
  if (!categoryTableBody) {
      return;
  }
  categoryTableBody.innerHTML = '';
  
  if (!categories || categories.length === 0) {
      categoryTableBody.innerHTML = '<tr><td colspan="4">暂无分类数据</td></tr>';
      return;
  }

  categories.forEach(categoryName => {
      const sites = categoryMap.get(categoryName) || [];
      const order = categoryOrderMap.has(categoryName) ? categoryOrderMap.get(categoryName) : 9999;
      
      const categoryRow = document.createElement('tr');
      categoryRow.className = 'category-row';
      categoryRow.setAttribute('data-category', categoryName);
      
      const nameCell = document.createElement('td');
      nameCell.colSpan = 2;
      
      const categoryHeader = document.createElement('div');
      categoryHeader.className = 'category-header';
      
      const expandIcon = document.createElement('span');
      expandIcon.className = 'expand-icon';
      expandIcon.innerHTML = \`
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 inline-block mr-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
          </svg>
      \`;
      
      const categoryNameSpan = document.createElement('span');
      categoryNameSpan.className = 'category-name';
      categoryNameSpan.textContent = categoryName;
      
      const editBtn = document.createElement('button');
      editBtn.className = 'category-edit-btn';
      editBtn.innerHTML = \`
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
          </svg>
      \`;
      editBtn.title = '编辑分类名称';
      
      const siteCount = document.createElement('span');
      siteCount.className = 'site-count';
      siteCount.textContent = \`(\${sites.length})\`;
      
      categoryHeader.appendChild(expandIcon);
      categoryHeader.appendChild(categoryNameSpan);
      categoryHeader.appendChild(editBtn);
      categoryHeader.appendChild(siteCount);
      nameCell.appendChild(categoryHeader);
      
      const sortCell = document.createElement('td');
      const input = document.createElement('input');
      input.type = 'number';
      input.className = 'category-sort-input';
      input.value = order;
      input.setAttribute('data-category', categoryName);
      sortCell.appendChild(input);
      
      const actionCell = document.createElement('td');
      actionCell.className = 'category-actions';
      
      const saveBtn = document.createElement('button');
      saveBtn.className = 'category-save-btn';
      saveBtn.textContent = '保存';
      saveBtn.setAttribute('data-category', categoryName);
      
      const resetBtn = document.createElement('button');
      resetBtn.className = 'category-reset-btn';
      resetBtn.textContent = '重置';
      resetBtn.setAttribute('data-category', categoryName);
      if (!categoryOrderMap.has(categoryName)) {
          resetBtn.disabled = true;
      }
      
      actionCell.appendChild(saveBtn);
      actionCell.appendChild(resetBtn);
      
      categoryRow.appendChild(nameCell);
      categoryRow.appendChild(sortCell);
      categoryRow.appendChild(actionCell);
      categoryTableBody.appendChild(categoryRow);
      
      const sitesContainer = document.createElement('tr');
      sitesContainer.className = 'sites-container';
      sitesContainer.style.display = 'none';
      
      const sitesCell = document.createElement('td');
      sitesCell.colSpan = 4;
      
      const sitesList = document.createElement('div');
      sitesList.className = 'sites-list';
      sitesList.setAttribute('data-category', categoryName);
      
      sites.forEach(site => {
          const siteItem = document.createElement('div');
          siteItem.className = 'site-item';
          siteItem.setAttribute('data-id', site.id);
          siteItem.setAttribute('data-category', categoryName);
          
          const siteInfo = document.createElement('div');
          siteInfo.className = 'site-info';
          
          const siteName = document.createElement('div');
          siteName.className = 'site-name';
          siteName.textContent = site.name || '未命名';
          
          const siteUrl = document.createElement('div');
          siteUrl.className = 'site-url';
          siteUrl.textContent = site.url || '';
          
          siteInfo.appendChild(siteName);
          siteInfo.appendChild(siteUrl);
          
          const siteActions = document.createElement('div');
          siteActions.className = 'site-actions';
          
          const editBtn = document.createElement('button');
          editBtn.className = 'edit-btn';
          editBtn.textContent = '编辑';
          editBtn.setAttribute('data-id', site.id);
          editBtn.addEventListener('click', () => handleEdit(site.id));
          
          const delBtn = document.createElement('button');
          delBtn.className = 'del-btn';
          delBtn.textContent = '删除';
          delBtn.setAttribute('data-id', site.id);
          delBtn.addEventListener('click', () => handleDelete(site.id));
          
          siteActions.appendChild(editBtn);
          siteActions.appendChild(delBtn);
          
          siteItem.appendChild(siteInfo);
          siteItem.appendChild(siteActions);
          sitesList.appendChild(siteItem);
      });
      
      sitesCell.appendChild(sitesList);
      sitesContainer.appendChild(sitesCell);
      categoryTableBody.appendChild(sitesContainer);
      
      categoryHeader.addEventListener('click', function(e) {
          // 如果点击的是编辑按钮，不展开/折叠
          if (e.target.closest('.category-edit-btn')) {
              return;
          }
          const isExpanded = sitesContainer.style.display !== 'none';
          sitesContainer.style.display = isExpanded ? 'none' : 'table-row';
          expandIcon.querySelector('svg').style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(90deg)';
      });
      
      // 编辑分类名称
      editBtn.addEventListener('click', function(e) {
          e.stopPropagation();
          const currentName = categoryNameSpan.textContent;
          const input = document.createElement('input');
          input.type = 'text';
          input.className = 'category-name-input';
          input.value = currentName;
          
          categoryNameSpan.style.display = 'none';
          editBtn.style.display = 'none';
          categoryHeader.insertBefore(input, categoryNameSpan);
          input.focus();
          input.select();
          
          const saveEdit = async () => {
              const newName = input.value.trim();
              if (!newName || newName === currentName) {
                  categoryHeader.removeChild(input);
                  categoryNameSpan.style.display = '';
                  editBtn.style.display = '';
                  return;
              }
              
              try {
                  // 更新所有该分类下的站点的分类名称
                  const sitesInCategory = categoryMap.get(currentName) || [];
                  const updatePromises = sitesInCategory.map(site => {
                      return fetch(\`/api/config/\${site.id}\`, {
                          method: 'PUT',
                          headers: {
                              'Content-Type': 'application/json'
                          },
                          body: JSON.stringify({
                              name: site.name,
                              url: site.url,
                              logo: site.logo,
                              desc: site.desc,
                              catelog: newName,
                              tags: site.tags,
                              sort_order: site.sort_order
                          })
                      });
                  });
                  
                  await Promise.all(updatePromises);
                  
                  // 更新分类排序表中的名称
                  if (categoryOrderMap.has(currentName)) {
                      await fetch('/api/categories/' + encodeURIComponent(newName), {
                          method: 'PUT',
                          headers: {
                              'Content-Type': 'application/json'
                          },
                          body: JSON.stringify({ sort_order: categoryOrderMap.get(currentName) })
                      });
                      
                      await fetch('/api/categories/' + encodeURIComponent(currentName), {
                          method: 'PUT',
                          headers: {
                              'Content-Type': 'application/json'
                          },
                          body: JSON.stringify({ reset: true })
                      });
                  }
                  
                  showMessage('分类名称更新成功', 'success');
                  fetchCategoriesWithSites();
              } catch (error) {
                  showMessage('更新失败: ' + error.message, 'error');
                  categoryHeader.removeChild(input);
                  categoryNameSpan.style.display = '';
                  editBtn.style.display = '';
              }
          };
          
          input.addEventListener('blur', saveEdit);
          input.addEventListener('keypress', function(e) {
              if (e.key === 'Enter') {
                  saveEdit();
              }
          });
      });
      
      new Sortable(sitesList, {
          group: 'sites',
          animation: 150,
          ghostClass: 'sortable-ghost',
          dragClass: 'sortable-drag',
          onEnd: function(evt) {
              saveOrderBtn.style.display = 'inline-block';
              saveOrderBtn.style.backgroundColor = '#dc3545';
          }
      });
  });
  
  bindCategoryEvents();
}

// 绑定分类事件
function bindCategoryEvents() {
  if (!categoryTableBody) {
      return;
  }
  
  categoryTableBody.querySelectorAll('.category-sort-input').forEach(input => {
      input.addEventListener('input', function() {
          const saveBtn = this.closest('tr').querySelector('.category-save-btn');
          if (saveBtn) {
              saveBtn.style.backgroundColor = '#dc3545';
          }
      });
  });
  
  categoryTableBody.querySelectorAll('.category-save-btn').forEach(btn => {
      btn.addEventListener('click', function() {
          const category = this.getAttribute('data-category');
          const input = this.closest('tr').querySelector('.category-sort-input');
          if (!category || !input) {
              return;
          }
          const rawValue = input.value.trim();
          if (rawValue === '') {
              showMessage('请输入排序值，或使用"重置"恢复默认。', 'error');
              return;
          }
          const sortValue = Number(rawValue);
          if (!Number.isFinite(sortValue)) {
              showMessage('排序值必须为数字', 'error');
              return;
          }
          
          this.disabled = true;
          this.textContent = '保存中...';
          
          fetch('/api/categories/' + encodeURIComponent(category), {
              method: 'PUT',
              headers: {
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify({ sort_order: sortValue })
          }).then(res => res.json())
              .then(data => {
                  this.disabled = false;
                  this.textContent = '保存';
                  
                  if (data.code === 200) {
                      showMessage('分类排序已更新', 'success');
                      this.style.backgroundColor = '';
                      
                      const categoryRow = this.closest('tr');
                      if (categoryRow) {
                          input.value = sortValue;
                          
                          const resetBtn = categoryRow.querySelector('.category-reset-btn');
                          if (resetBtn) {
                              resetBtn.disabled = false;
                          }
                      }
                      
                      fetchCategoriesWithSites();
                  } else {
                      showMessage(data.message || '更新失败', 'error');
                  }
              }).catch(() => {
                  this.disabled = false;
                  this.textContent = '保存';
                  showMessage('网络错误', 'error');
              });
      });
  });

  categoryTableBody.querySelectorAll('.category-reset-btn').forEach(btn => {
      btn.addEventListener('click', function() {
          if (this.disabled) {
              return;
          }
          const category = this.getAttribute('data-category');
          if (!category) {
              return;
          }
          if (!confirm('确定恢复该分类的默认排序吗？')) {
              return;
          }
          
          this.disabled = true;
          this.textContent = '重置中...';
          
          fetch('/api/categories/' + encodeURIComponent(category), {
              method: 'PUT',
              headers: {
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify({ reset: true })
          }).then(res => res.json())
              .then(data => {
                  this.disabled = false;
                  this.textContent = '重置';
                  
                  if (data.code === 200) {
                      showMessage('已重置分类排序', 'success');
                      
                      const categoryRow = this.closest('tr');
                      if (categoryRow) {
                          const input = categoryRow.querySelector('.category-sort-input');
                          if (input) {
                              const categoryName = this.getAttribute('data-category');
                              const sites = categoriesData.get(categoryName) || [];
                              let minSort = 9999;
                              sites.forEach(site => {
                                  const siteSort = normalizeSortOrder(site.sort_order);
                                  if (siteSort < minSort) {
                                      minSort = siteSort;
                                  }
                              });
                              input.value = minSort;
                          }
                          
                          this.disabled = true;
                      }
                      
                      fetchCategoriesWithSites();
                  } else {
                      showMessage(data.message || '重置失败', 'error');
                  }
              }).catch(() => {
                  this.disabled = false;
                  this.textContent = '重置';
                  showMessage('网络错误', 'error');
              });
      });
  });
}

// 编辑站点
function handleEdit(id) {
  fetch(\`/api/config/\${id}\`)
  .then(res => res.json())
  .then(data => {
      if (data.code !== 200) {
          showMessage('找不到要编辑的数据', 'error');
          return;
      }
      const configToEdit = data.data;
      document.getElementById('editId').value = configToEdit.id;
      document.getElementById('editName').value = configToEdit.name;
      document.getElementById('editUrl').value = configToEdit.url;
      document.getElementById('editLogo').value = configToEdit.logo || '';
      document.getElementById('editDesc').value = configToEdit.desc || '';
      document.getElementById('editCatelog').value = configToEdit.catelog;
      document.getElementById('editTags').value = configToEdit.tags || '';
      document.getElementById('editSortOrder').value = configToEdit.sort_order === 9999 ? '' : configToEdit.sort_order;
      
      editModal.style.display = 'block';
  }).catch(err => {
      showMessage('网络错误', 'error');
  });
}

// 删除站点
function handleDelete(id) {
  if(!confirm('确认删除？')) return;
   fetch(\`/api/config/\${id}\`, {
        method: 'DELETE'
    }).then(res => res.json())
       .then(data => {
           if (data.code === 200) {
               showMessage('删除成功', 'success');
               fetchCategoriesWithSites();
           } else {
               showMessage(data.message, 'error');
           }
       }).catch(err => {
            showMessage('网络错误', 'error');
       })
}

// 显示消息
function showMessage(message, type) {
  messageDiv.innerText = message;
  messageDiv.className = type;
  messageDiv.style.display = 'block';
  setTimeout(() => {
      messageDiv.style.display = 'none';
  }, 3000);
}

// 添加站点
addBtn.addEventListener('click', () => {
  const name = addName.value;
  const url = addUrl.value;
  const logo = addLogo.value;
  const desc = addDesc.value;
  const catelog = addCatelog.value;
  const tags = addTags.value;
  const sort_order = addSortOrder.value;
  if(!name || !url || !catelog) {
    showMessage('名称,URL,分类 必填', 'error');
    return;
  }
  const payload = {
     name: name.trim(),
     url: url.trim(),
     logo: logo.trim(),
     desc: desc.trim(),
     catelog: catelog.trim(),
     tags: tags.trim()
  };
  if (sort_order !== '') {
     payload.sort_order = Number(sort_order);
  }
  fetch('/api/config', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  }).then(res => res.json())
  .then(data => {
     if(data.code === 201) {
         showMessage('添加成功', 'success');
        addName.value = '';
        addUrl.value = '';
        addLogo.value = '';
        addDesc.value = '';
        addCatelog.value = '';
        addTags.value = '';
        addSortOrder.value = '';
         fetchCategoriesWithSites();
     }else {
        showMessage(data.message, 'error');
     }
  }).catch(err => {
    showMessage('网络错误', 'error');
  })
});

// 导入
importBtn.addEventListener('click', () => {
  importFile.click();
});

importFile.addEventListener('change', function(e) {
  const file = e.target.files[0];
  if (file) {
   const reader = new FileReader();
  reader.onload = function(event) {
     try {
         const jsonData = JSON.parse(event.target.result);
           fetch('/api/config/import', {
               method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
               body: JSON.stringify(jsonData)
          }).then(res => res.json())
             .then(data => {
                  if(data.code === 201) {
                     showMessage('导入成功', 'success');
                      fetchCategoriesWithSites();
                  } else {
                     showMessage(data.message, 'error');
                  }
             }).catch(err => {
                   showMessage('网络错误', 'error');
          })
  
     } catch (error) {
           showMessage('JSON格式不正确', 'error');
     }
  }
   reader.readAsText(file);
  }
});

// 导出
exportBtn.addEventListener('click', () => {
  fetch('/api/config/export')
  .then(res => res.blob())
  .then(blob => {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'config.json';
  document.body.appendChild(a);
  a.click();
   window.URL.revokeObjectURL(url);
   document.body.removeChild(a);
  }).catch(err => {
  showMessage('网络错误', 'error');
  })
});

// 获取待审核
function fetchPendingConfigs(page = pendingCurrentPage) {
      fetch(\`/api/pending?page=\${page}&pageSize=\${pendingPageSize}\`)
          .then(res => res.json())
          .then(data => {
            if (data.code === 200) {
                   pendingTotalItems = data.total;
                   pendingCurrentPage = data.page;
                   pendingTotalPagesSpan.innerText = Math.ceil(pendingTotalItems/ pendingPageSize);
                    pendingCurrentPageSpan.innerText = pendingCurrentPage;
                   allPendingConfigs = data.data;
                     renderPendingConfig(allPendingConfigs);
                    updatePendingPaginationButtons();
            } else {
                showMessage(data.message, 'error');
            }
          }).catch(err => {
          showMessage('网络错误', 'error');
       })
}

// 渲染待审核
function renderPendingConfig(configs) {
      pendingTableBody.innerHTML = '';
      if(configs.length === 0) {
          pendingTableBody.innerHTML = '<tr><td colspan="8">没有待审核数据</td></tr>';
          return
      }
    configs.forEach(config => {
        const row = document.createElement('tr');
        const safeName = escapeHTML(config.name || '');
        const normalizedUrl = normalizeUrl(config.url);
        const urlCell = normalizedUrl
          ? \`<a href="\${escapeHTML(normalizedUrl)}" target="_blank" rel="noopener noreferrer">\${escapeHTML(normalizedUrl)}</a>\`
          : (config.url ? escapeHTML(config.url) : '未提供');
        const normalizedLogo = normalizeUrl(config.logo);
        const logoCell = normalizedLogo
          ? \`<img src="\${escapeHTML(normalizedLogo)}" alt="\${safeName}" style="width:30px;" />\`
          : 'N/A';
        const descCell = config.desc ? escapeHTML(config.desc) : 'N/A';
        const catelogCell = escapeHTML(config.catelog || '');
        const tagsCell = config.tags ? escapeHTML(config.tags) : 'N/A';
        row.innerHTML = \`
          <td>\${config.id}</td>
           <td>\${safeName}</td>
           <td>\${urlCell}</td>
           <td>\${logoCell}</td>
           <td>\${descCell}</td>
           <td>\${catelogCell}</td>
           <td>\${tagsCell}</td>
            <td class="actions">
                <button class="approve-btn" data-id="\${config.id}">批准</button>
              <button class="reject-btn" data-id="\${config.id}">拒绝</button>
            </td>
          \`;
        pendingTableBody.appendChild(row);
    });
    bindPendingActionEvents();
}

// 绑定待审核操作
function bindPendingActionEvents() {
    document.querySelectorAll('.approve-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = this.dataset.id;
            handleApprove(id);
        })
    });
   document.querySelectorAll('.reject-btn').forEach(btn => {
         btn.addEventListener('click', function() {
              const id = this.dataset.id;
              handleReject(id);
          })
   })
}

// 批准
function handleApprove(id) {
   if (!confirm('确定批准吗？')) return;
   fetch(\`/api/pending/\${id}\`, {
         method: 'PUT',
       }).then(res => res.json())
     .then(data => {
          if (data.code === 200) {
              showMessage('批准成功', 'success');
              fetchPendingConfigs();
               fetchCategoriesWithSites();
          } else {
               showMessage(data.message, 'error')
            }
       }).catch(err => {
             showMessage('网络错误', 'error');
         })
}

// 拒绝
function handleReject(id) {
    if (!confirm('确定拒绝吗？')) return;
   fetch(\`/api/pending/\${id}\`, {
          method: 'DELETE'
     }).then(res => res.json())
        .then(data => {
          if(data.code === 200) {
              showMessage('拒绝成功', 'success');
             fetchPendingConfigs();
         } else {
            showMessage(data.message, 'error');
        }
       }).catch(err => {
             showMessage('网络错误', 'error');
     })
}

// 更新分页按钮
function updatePendingPaginationButtons() {
    pendingPrevPageBtn.disabled = pendingCurrentPage === 1;
     pendingNextPageBtn.disabled = pendingCurrentPage >= Math.ceil(pendingTotalItems/ pendingPageSize)
 }

 pendingPrevPageBtn.addEventListener('click', () => {
     if (pendingCurrentPage > 1) {
         fetchPendingConfigs(pendingCurrentPage - 1);
     }
 });

  pendingNextPageBtn.addEventListener('click', () => {
     if (pendingCurrentPage < Math.ceil(pendingTotalItems/pendingPageSize)) {
         fetchPendingConfigs(pendingCurrentPage + 1)
     }
  });

// 初始化
fetchCategoriesWithSites();
fetchPendingConfigs();`
    };
    return fileContents[filePath];
  },

  async renderAdminPage() {
    const html = await this.getFileContent('admin.html');
    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  },

  async renderLoginPage(message = '') {
    const hasError = Boolean(message);
    const safeMessage = hasError ? escapeHTML(message) : '';
    const html = `<!DOCTYPE html>
      <html lang="zh-CN">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>管理员登录</title>
        <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
          *, *::before, *::after {
            box-sizing: border-box;
          }
          
          html, body {
            height: 100%;
            margin: 0;
            padding: 0;
            font-family: 'Noto Sans SC', sans-serif;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
          }

          body {
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: #f8f9fa;
            padding: 1rem;
          }

          .login-container {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08), 0 4px 12px rgba(15, 23, 42, 0.05);
            width: 100%;
            max-width: 380px;
            animation: fadeIn 0.5s ease-out;
          }
          
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(-10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          .login-title {
            font-size: 1.75rem;
            font-weight: 700;
            text-align: center;
            margin: 0 0 1.5rem 0;
            color: #333;
          }

          .form-group {
            margin-bottom: 1.25rem;
          }

          label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #555;
          }

          input[type="text"], input[type="password"] {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
          }

          input:focus {
            border-color: #7209b7;
            outline: none;
            box-shadow: 0 0 0 3px rgba(114, 9, 183, 0.15);
          }

          button {
            width: 100%;
            padding: 0.875rem;
            background-color: #7209b7;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s, transform 0.1s;
          }

          button:hover {
            background-color: #5a067c;
          }
          
          button:active {
            transform: scale(0.98);
          }

          .error-message {
            color: #dc3545;
            font-size: 0.875rem;
            margin-top: 0.5rem;
            text-align: center;
            display: none;
          }

          .back-link {
            display: block;
            text-align: center;
            margin-top: 1.5rem;
            color: #7209b7;
            text-decoration: none;
            font-size: 0.875rem;
          }

          .back-link:hover {
            text-decoration: underline;
          }
        </style>
      </head>
      <body>
        <div class="login-container">
          <h1 class="login-title">管理员登录</h1>
          <form method="post" action="/admin" novalidate>
            <div class="form-group">
              <label for="username">用户名</label>
              <input type="text" id="username" name="name" required autocomplete="username">
            </div>
            <div class="form-group">
              <label for="password">密码</label>
              <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            ${hasError ? `<div class="error-message" style="display:block;">${safeMessage}</div>` : `<div class="error-message">用户名或密码错误</div>`}
            <button type="submit">登 录</button>
          </form>
          <a href="/" class="back-link">返回首页</a>
        </div>
      </body>
      </html>`;
      
      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
  }
};

// ========== 主页渲染 ==========
async function handleRequest(request, env, ctx) {
  // 请求限流
  try {
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateLimitKey = `rate_limit:${clientIP}`;
    const currentCount = await env.NAV_CACHE.get(rateLimitKey) || '0';
    if (parseInt(currentCount) > 100) {
      return new Response('Too Many Requests', { status: 429 });
    }
    await env.NAV_CACHE.put(rateLimitKey, (parseInt(currentCount) + 1).toString(), {
      expirationTtl: 60
    });
  } catch (e) {
    // KV可能未绑定，忽略错误
  }

  const url = new URL(request.url);
  const catalog = url.searchParams.get('catalog');
  const tag = url.searchParams.get('tag');

  let sites = [];
  try {
    const { results } = await env.NAV_DB.prepare('SELECT * FROM sites ORDER BY sort_order ASC, create_time DESC').all();
    sites = results;
  } catch (e) {
    return new Response(`Failed to fetch data: ${e.message}`, { status: 500 });
  }

  if (!sites || sites.length === 0) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>精灵导航网</title>
  <link rel="icon" href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png">
  <link rel="shortcut icon" href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png">
  <link rel="apple-touch-icon" href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png">
  <link href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png" rel="stylesheet"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            primary: {
              50: '#f3f5f9',
              100: '#e1e7f1',
              200: '#c3d0e3',
              300: '#9cb3d1',
              400: '#6c8fba',
              500: '#416d9d',
              600: '#305580',
              700: '#254267',
              800: '#1d3552',
              900: '#192e45',
              950: '#101e2d',
            },
            secondary: {
              50: '#fdf8f3',
              100: '#f6ede1',
              200: '#ead6ba',
              300: '#dfc19a',
              400: '#d2aa79',
              500: '#b88d58',
              600: '#a17546',
              700: '#835b36',
              800: '#6b492c',
              900: '#5a3e26',
              950: '#2f1f13',
            },
            accent: {
              50: '#f2faf6',
              100: '#d9f0e5',
              200: '#b4dfcb',
              300: '#89caa9',
              400: '#61b48a',
              500: '#3c976d',
              600: '#2e7755',
              700: '#265c44',
              800: '#204b38',
              900: '#1b3e30',
              950: '#0e221b',
            },
          },
          fontFamily: {
            sans: ['Noto Sans SC', 'sans-serif'],
          },
        }
      }
  </script>
  <style>
    /* 自定义滚动条 */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: #f1f5f9;
      border-radius: 10px;
    }
    ::-webkit-scrollbar-thumb {
      background: #cbd5e1;
      border-radius: 10px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: #94a3b8;
    }
    
    /* 卡片悬停效果 */
    .site-card {
      transition: transform 0.2s ease, box-shadow 0.2s ease;
      position: relative;
    }
    .site-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
    
    /* 卡片描述悬停显示 */
    .site-card .description {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      background: rgba(0, 0, 0, 0.8);
      color: white;
      padding: 8px;
      border-radius: 0 0 6px 6px;
      transform: translateY(100%);
      transition: transform 0.2s ease;
      z-index: 10;
      font-size: 12px;
    }
    .site-card:hover .description {
      transform: translateY(0);
    }
    
    /* 复制成功提示动画 */
    @keyframes fadeInOut {
      0% { opacity: 0; transform: translateY(10px); }
      20% { opacity: 1; transform: translateY(0); }
      80% { opacity: 1; transform: translateY(0); }
      100% { opacity: 0; transform: translateY(-10px); }
    }
    .copy-success-animation {
      animation: fadeInOut 2s ease forwards;
    }
    
    /* 移动端侧边栏 */
    @media (max-width: 768px) {
      .mobile-sidebar {
        transform: translateX(-100%);
        transition: transform 0.3s ease;
      }
      .mobile-sidebar.open {
        transform: translateX(0);
      }
      .mobile-overlay {
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.3s ease;
      }
      .mobile-overlay.open {
        opacity: 1;
        pointer-events: auto;
      }
    }
    
    /* 搜索引擎下拉菜单 */
    .search-engine-dropdown {
      position: relative;
    }
    .search-engine-menu {
      position: absolute;
      top: 100%;
      right: 0;
      background: white;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      z-index: 50;
      min-width: 150px;
      display: none;
    }
    .search-engine-menu.show {
      display: block;
    }
    .search-engine-option {
      padding: 8px 12px;
      cursor: pointer;
      transition: background-color 0.2s;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .search-engine-option:hover {
      background-color: #f1f5f9;
    }
    .search-engine-option.active {
      background-color: #e1e7f1;
      font-weight: 500;
    }
    
    /* 网站预览弹窗 */
    .preview-modal {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.3s, visibility 0.3s;
    }
    .preview-modal.show {
      opacity: 1;
      visibility: visible;
    }
    .preview-content {
      background: white;
      border-radius: 12px;
      width: 90%;
      max-width: 800px;
      height: 80%;
      display: flex;
      flex-direction: column;
      transform: scale(0.9);
      transition: transform 0.3s;
    }
    .preview-modal.show .preview-content {
      transform: scale(1);
    }
    .preview-header {
      padding: 16px;
      border-bottom: 1px solid #e1e7f1;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .preview-body {
      flex: 1;
      padding: 0;
      overflow: hidden;
    }
    .preview-iframe {
      width: 100%;
      height: 100%;
      border: none;
    }
    
    /* 图片懒加载 */
    .lazy-image {
      opacity: 0;
      transition: opacity 0.3s;
    }
    .lazy-image.loaded {
      opacity: 1;
    }
    
    /* 拖拽排序 */
    .sortable-ghost {
      opacity: 0.4;
      background-color: #f0f8ff;
    }
    .sortable-drag {
      opacity: 0.9;
    }
    
    /* 侧边栏控制 */
    #sidebar-toggle {
      display: none;
    }
    
    @media (min-width: 769px) {
      #sidebar-toggle:checked ~ .sidebar {
        margin-left: -16rem;
      }
      #sidebar-toggle:checked ~ .main-content {
        margin-left: 0;
      }
    }
  </style>
</head>
<body class="bg-slate-50 font-sans text-gray-800">
  <!-- 侧边栏开关 -->
  <input type="checkbox" id="sidebar-toggle" class="hidden">
  
  <!-- 移动端导航按钮 -->
  <div class="fixed top-4 left-4 z-50 lg:hidden">
    <button id="sidebarToggle" class="p-2 rounded-lg bg-white shadow-md hover:bg-gray-100">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </button>
  </div>
  
  <!-- 移动端遮罩层 -->
  <div id="mobileOverlay" class="fixed inset-0 bg-black bg-opacity-50 z-40 mobile-overlay lg:hidden"></div>
  
  <!-- 桌面侧边栏开关按钮 -->
  <div class="fixed top-4 left-4 z-50 hidden lg:block">
    <label for="sidebar-toggle" class="p-2 rounded-lg bg-white shadow-md hover:bg-gray-100 inline-block cursor-pointer">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </label>
  </div>
  
  <!-- 侧边栏导航 -->
  <aside id="sidebar" class="sidebar fixed left-0 top-0 h-full w-64 bg-white shadow-md border-r border-slate-200 z-50 overflow-y-auto mobile-sidebar lg:transform-none transition-all duration-300">
    <div class="p-6">
      <div class="flex items-center justify-between mb-8">
        <h2 class="text-2xl font-bold text-primary-600 tracking-tight">精灵导航网</h2>
        <button id="closeSidebar" class="p-1 rounded-full hover:bg-gray-100 lg:hidden">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
        <label for="sidebar-toggle" class="p-1 rounded-full hover:bg-gray-100 hidden lg:block cursor-pointer">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </label>
      </div>
      
      <div class="mb-6">
        <div class="relative">
          <input id="searchInput" type="text" placeholder="搜索书签..." class="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400 transition">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-400 absolute left-3 top-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>
      
      <div>
        <h3 class="text-sm font-medium text-gray-500 uppercase tracking-wider mb-3">分类导航</h3>
        <div class="space-y-1">
          <a href="?" class="flex items-center px-3 py-2 rounded-lg bg-slate-100 text-primary-700 w-full">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2 text-primary-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            全部
          </a>
        </div>
      </div>
      
      <div class="mt-8 pt-6 border-t border-gray-200">
        <a href="https://www.wangwangit.com/" target="_blank" class="flex items-center px-4 py-2 text-gray-600 hover:text-primary-500 transition duration-300">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
          </svg>
          访问博客
        </a>

        <a href="/admin" target="_blank" class="mt-4 flex items-center px-4 py-2 text-gray-600 hover:text-primary-500 transition duration-300">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-1.065-2.573c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          后台管理
        </a>
      </div>
    </div>
  </aside>
  
  <!-- 主内容区 -->
  <main class="main-content lg:ml-64 min-h-screen transition-all duration-300">
    <!-- 搜索区域 -->
    <header class="bg-white shadow-sm p-4 sticky top-0 z-10">
      <div class="max-w-4xl mx-auto flex flex-col items-center gap-4">
        <!-- 左侧：标题和统计 -->
        <div class="flex items-center gap-4 w-full">
          <h1 class="text-xl font-bold flex items-center gap-2">
            <span id="categoryTitle">暂无书签数据</span>
            <span class="text-sm font-normal text-gray-500">(<span id="siteCount">0</span>)</span>
          </h1>
          <div class="ml-auto flex items-center gap-2">
            <button id="enableDragSort" class="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <span class="text-sm text-gray-500">拖拽排序</span>
          </div>
        </div>
        
        <!-- 中间：搜索框 -->
        <div class="relative w-full max-w-2xl">
          <input id="mainSearchInput" type="text" placeholder="搜索..." 
                 class="w-full px-4 py-2 pr-24 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent">
          <div class="absolute right-0 top-0 h-full flex items-center">
            <!-- 搜索引擎选择按钮 -->
            <div class="search-engine-dropdown">
              <button id="searchEngineBtn" class="px-3 py-2 h-full flex items-center gap-1 text-sm bg-gray-100 hover:bg-gray-200 rounded-r-lg transition-colors">
                <span id="currentEngine">站内</span>
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              <div id="searchEngineMenu" class="search-engine-menu">
                <div class="search-engine-option active" data-engine="site">
                  <i class="fas fa-search"></i>
                  <span>站内搜索</span>
                </div>
                <div class="search-engine-option" data-engine="google">
                  <i class="fab fa-google"></i>
                  <span>Google</span>
                </div>
                <div class="search-engine-option" data-engine="baidu">
                  <i class="fas fa-paw"></i>
                  <span>百度</span>
                </div>
                <div class="search-engine-option" data-engine="bing">
                  <i class="fab fa-microsoft"></i>
                  <span>Bing</span>
                </div>
                <div class="search-engine-option" data-engine="github">
                  <i class="fab fa-github"></i>
                  <span>GitHub</span>
                </div>
              </div>
            </div>
            <!-- 搜索按钮 -->
            <button id="searchButton" class="ml-1 px-3 py-2 h-full bg-primary-500 text-white rounded-r-lg hover:bg-primary-600 transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </header>
    
    <!-- 网站列表 -->
    <section class="max-w-7xl mx-auto px-4 sm:px-6 py-8">
      <div class="rounded-2xl border border-slate-200 bg-white p-4 sm:p-6 shadow-sm">
        <div id="sitesGrid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4">
          <div class="text-center py-16">
            <h2 class="text-2xl font-semibold text-gray-800 mb-4">暂无书签数据</h2>
            <p class="text-gray-600">管理员尚未添加任何网站书签，请稍后再试。</p>
          </div>
        </div>
      </div>
    </section>
  </main>
  
  <!-- 网站预览弹窗 -->
  <div id="previewModal" class="preview-modal">
    <div class="preview-content">
      <div class="preview-header">
        <h3 id="previewTitle" class="text-lg font-medium">网站预览</h3>
        <button id="closePreview" class="p-1 rounded-full hover:bg-gray-100">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
      <div class="preview-body">
        <iframe id="previewIframe" class="preview-iframe" src="" sandbox="allow-same-origin allow-scripts allow-forms"></iframe>
      </div>
    </div>
  </div>
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // 侧边栏控制
      const sidebar = document.getElementById('sidebar');
      const mobileOverlay = document.getElementById('mobileOverlay');
      const sidebarToggle = document.getElementById('sidebarToggle');
      const closeSidebar = document.getElementById('closeSidebar');
      
      function openSidebar() {
        sidebar.classList.add('open');
        mobileOverlay.classList.add('open');
        document.body.style.overflow = 'hidden';
      }
      
      function closeSidebarMenu() {
        sidebar.classList.remove('open');
        mobileOverlay.classList.remove('open');
        document.body.style.overflow = '';
      }
      
      if (sidebarToggle) sidebarToggle.addEventListener('click', openSidebar);
      if (closeSidebar) closeSidebar.addEventListener('click', closeSidebarMenu);
      if (mobileOverlay) mobileOverlay.addEventListener('click', closeSidebarMenu);
      
      // 搜索引擎下拉菜单
      const searchEngineBtn = document.getElementById('searchEngineBtn');
      const searchEngineMenu = document.getElementById('searchEngineMenu');
      const currentEngine = document.getElementById('currentEngine');
      const searchEngineOptions = document.querySelectorAll('.search-engine-option');
      
      searchEngineBtn.addEventListener('click', function() {
        searchEngineMenu.classList.toggle('show');
      });
      
      searchEngineOptions.forEach(option => {
        option.addEventListener('click', function() {
          searchEngineOptions.forEach(opt => opt.classList.remove('active'));
          this.classList.add('active');
          currentEngine.textContent = this.querySelector('span').textContent;
          searchEngineMenu.classList.remove('show');
        });
      });
      
      // 点击外部关闭下拉菜单
      document.addEventListener('click', function(e) {
        if (!searchEngineBtn.contains(e.target) && !searchEngineMenu.contains(e.target)) {
          searchEngineMenu.classList.remove('show');
        }
      });
      
      // 搜索功能
      const mainSearchInput = document.getElementById('mainSearchInput');
      const searchButton = document.getElementById('searchButton');
      
      function performSearch() {
        const activeOption = document.querySelector('.search-engine-option.active');
        const engine = activeOption ? activeOption.dataset.engine : 'site';
        const query = mainSearchInput.value.trim();
        
        if (!query) return;
        
        switch(engine) {
          case 'google':
            window.open(\`https://www.google.com/search?q=\${encodeURIComponent(query)}\`, '_blank');
            break;
          case 'baidu':
            window.open(\`https://www.baidu.com/s?wd=\${encodeURIComponent(query)}\`, '_blank');
            break;
          case 'bing':
            window.open(\`https://www.bing.com/search?q=\${encodeURIComponent(query)}\`, '_blank');
            break;
          case 'github':
            window.open(\`https://github.com/search?q=\${encodeURIComponent(query)}\`, '_blank');
            break;
          default:
            // 站内搜索
            const url = new URL(window.location);
            url.searchParams.set('keyword', query);
            url.searchParams.delete('catalog');
            url.searchParams.delete('tag');
            window.location.href = url.toString();
        }
      }
      
      if (searchButton) {
        searchButton.addEventListener('click', performSearch);
      }
      
      if (mainSearchInput) {
        mainSearchInput.addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            performSearch();
          }
        });
      }
      
      // 站内搜索功能
      const searchInput = document.getElementById('searchInput');
      const sitesGrid = document.getElementById('sitesGrid');
      
      if (searchInput && sitesGrid) {
        searchInput.addEventListener('input', function() {
          const keyword = this.value.toLowerCase().trim();
          const siteCards = sitesGrid.querySelectorAll('.site-card');
          
          siteCards.forEach(card => {
            const name = (card.getAttribute('data-name') || '').toLowerCase();
            const url = (card.getAttribute('data-url') || '').toLowerCase();
            const catalogValue = (card.getAttribute('data-catalog') || '').toLowerCase();
            
            if (name.includes(keyword) || url.includes(keyword) || catalogValue.includes(keyword)) {
              card.classList.remove('hidden');
            } else {
              card.classList.add('hidden');
            }
          });
          
          // 更新计数
          const visibleCards = sitesGrid.querySelectorAll('.site-card:not(.hidden)');
          const siteCount = document.getElementById('siteCount');
          if (siteCount) {
            siteCount.textContent = visibleCards.length;
          }
        });
      }
      
      // 网站预览功能
      const previewModal = document.getElementById('previewModal');
      const previewIframe = document.getElementById('previewIframe');
      const previewTitle = document.getElementById('previewTitle');
      const closePreview = document.getElementById('closePreview');
      
      // 为所有预览按钮添加事件
      document.addEventListener('click', function(e) {
        if (e.target.closest('.preview-btn')) {
          const btn = e.target.closest('.preview-btn');
          const url = btn.getAttribute('data-url');
          const siteName = btn.closest('.site-card').getAttribute('data-name');
          
          if (url && url !== '#') {
            previewTitle.textContent = \`预览: \${siteName}\`;
            previewIframe.src = url;
            previewModal.classList.add('show');
          }
        }
      });
      
      if (closePreview) {
        closePreview.addEventListener('click', function() {
          previewModal.classList.remove('show');
          previewIframe.src = '';
        });
      }
      
      previewModal.addEventListener('click', function(e) {
        if (e.target === previewModal) {
          previewModal.classList.remove('show');
          previewIframe.src = '';
        }
      });
      
      // 图片懒加载
      const lazyImages = document.querySelectorAll('.lazy-image');
      const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const img = entry.target;
            img.src = img.dataset.src;
            img.classList.add('loaded');
            observer.unobserve(img);
          }
        });
      });
      
      lazyImages.forEach(img => imageObserver.observe(img));
      
      // 拖拽排序功能
      let sortableInstance = null;
      const enableDragSort = document.getElementById('enableDragSort');
      const sitesGridContainer = document.getElementById('sitesGrid');
      
      // 从localStorage读取排序
      function loadCustomOrder() {
        const customOrder = localStorage.getItem('siteCustomOrder');
        if (customOrder) {
          try {
            const orderData = JSON.parse(customOrder);
            const siteCards = Array.from(sitesGridContainer.querySelectorAll('.site-card'));
            
            // 按照保存的顺序重新排列卡片
            orderData.forEach(id => {
              const card = siteCards.find(c => c.getAttribute('data-id') === id);
              if (card) {
                sitesGridContainer.appendChild(card);
              }
            });
          } catch (e) {
            console.error('Failed to load custom order:', e);
          }
        }
      }
      
      // 保存排序到localStorage
      function saveCustomOrder() {
        const siteCards = Array.from(sitesGridContainer.querySelectorAll('.site-card'));
        const orderData = siteCards.map(card => card.getAttribute('data-id'));
        localStorage.setItem('siteCustomOrder', JSON.stringify(orderData));
      }
      
      if (enableDragSort && sitesGridContainer) {
        enableDragSort.addEventListener('click', function() {
          if (sortableInstance) {
            sortableInstance.destroy();
            sortableInstance = null;
            this.classList.remove('bg-primary-500', 'text-white');
            this.classList.add('bg-gray-100');
          } else {
            sortableInstance = new Sortable(sitesGridContainer, {
              animation: 150,
              ghostClass: 'sortable-ghost',
              dragClass: 'sortable-drag',
              onEnd: function(evt) {
                saveCustomOrder();
              }
            });
            this.classList.remove('bg-gray-100');
            this.classList.add('bg-primary-500', 'text-white');
          }
        });
      }
      
      // 页面加载时应用自定义排序
      setTimeout(() => {
        loadCustomOrder();
      }, 100);
    });
  </script>
</body>
</html>`;
    return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' }});
  }

  const totalSites = sites.length;
  const categoryMinSort = new Map();
  const categorySet = new Set();
  sites.forEach((site) => {
    const categoryName = (site.catelog || '').trim() || '未分类';
    categorySet.add(categoryName);
    const rawSort = Number(site.sort_order);
    const normalized = Number.isFinite(rawSort) ? rawSort : 9999;
    if (!categoryMinSort.has(categoryName) || normalized < categoryMinSort.get(categoryName)) {
      categoryMinSort.set(categoryName, normalized);
    }
  });

  const categoryOrderMap = new Map();
  try {
    const { results: orderRows } = await env.NAV_DB.prepare('SELECT catelog, sort_order FROM category_orders').all();
    orderRows.forEach(row => {
      categoryOrderMap.set(row.catelog, normalizeSortOrder(row.sort_order));
    });
  } catch (error) {
    if (!/no such table/i.test(error.message || '')) {
      return new Response(`Failed to fetch category orders: ${error.message}`, { status: 500 });
    }
  }

  const catalogsWithMeta = Array.from(categorySet).map((name) => {
    const fallbackSort = categoryMinSort.has(name) ? normalizeSortOrder(categoryMinSort.get(name)) : 9999;
    const order = categoryOrderMap.has(name) ? categoryOrderMap.get(name) : fallbackSort;
    return {
      name,
      order,
      fallback: fallbackSort,
    };
  });

  catalogsWithMeta.sort((a, b) => {
    if (a.order !== b.order) {
      return a.order - b.order;
    }
    if (a.fallback !== b.fallback) {
      return a.fallback - b.fallback;
    }
    return a.name.localeCompare(b.name, 'zh-Hans-CN', { sensitivity: 'base' });
  });

  const catalogs = catalogsWithMeta.map(item => item.name);
  
  const allTagsSet = new Set();
  sites.forEach(site => {
    if (site.tags) {
      const tags = site.tags.split(',').map(tag => tag.trim());
      tags.forEach(tag => {
        if (tag) allTagsSet.add(tag);
      });
    }
  });
  const allTags = Array.from(allTagsSet).sort();
  
  const requestedCatalog = (catalog || '').trim();
  const requestedTag = (tag || '').trim();
  const catalogExists = Boolean(requestedCatalog && catalogs.includes(requestedCatalog));
  const tagExists = Boolean(requestedTag && allTags.includes(requestedTag));
  
  let currentSites = sites;
  let currentCatalog = '';
  
  if (catalogExists) {
    currentCatalog = requestedCatalog;
    currentSites = currentSites.filter((s) => {
      const catValue = (s.catelog || '').trim() || '未分类';
      return catValue === requestedCatalog;
    });
  }
  
  if (tagExists) {
    currentSites = currentSites.filter((s) => {
      if (!s.tags) return false;
      const tags = s.tags.split(',').map(tag => tag.trim());
      return tags.includes(requestedTag);
    });
  }
  
  const catalogLinkMarkup = catalogs.map((cat) => {
    const safeCat = escapeHTML(cat);
    const encodedCat = encodeURIComponent(cat);
    const isActive = catalogExists && cat === currentCatalog;
    const linkClass = isActive ? 'bg-slate-100 text-primary-700' : 'hover:bg-gray-100';
    const iconClass = isActive ? 'text-primary-600' : 'text-gray-400';
    return `
      <a href="?catalog=${encodedCat}" class="flex items-center px-3 py-2 rounded-lg ${linkClass} w-full">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2 ${iconClass}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
        </svg>
        ${safeCat}
      </a>
    `;
  }).join('');

  const tagLinkMarkup = allTags.map((tag) => {
    const safeTag = escapeHTML(tag);
    const encodedTag = encodeURIComponent(tag);
    const isActive = tagExists && tag === requestedTag;
    const linkClass = isActive ? 'bg-slate-100 text-primary-700' : 'hover:bg-gray-100';
    return `
      <a href="?tag=${encodedTag}" class="inline-block px-3 py-1 m-1 rounded-full text-sm ${linkClass}">
        #${safeTag}
      </a>
    `;
  }).join('');

  const datalistOptions = catalogs.map((cat) => `<option value="${escapeHTML(cat)}">`).join('');
  
  // 优化后的标题显示
  let titleText = '';
  let titleCount = currentSites.length;
  if (catalogExists) {
    titleText = currentCatalog;
  } else if (tagExists) {
    titleText = `#${requestedTag}`;
  } else {
    titleText = '全部收藏';
  }
  
  const submissionEnabled = isSubmissionEnabled(env);

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>精灵导航网</title>
  <link rel="icon" href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png">
  <link rel="shortcut icon" href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png">
  <link rel="apple-touch-icon" href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png">
  <link href="https://img.icons8.com/?size=160&id=1C7GGjJBWQzh&format=png" rel="stylesheet"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            primary: {
              50: '#f3f5f9',
              100: '#e1e7f1',
              200: '#c3d0e3',
              300: '#9cb3d1',
              400: '#6c8fba',
              500: '#416d9d',
              600: '#305580',
              700: '#254267',
              800: '#1d3552',
              900: '#192e45',
              950: '#101e2d',
            },
            secondary: {
              50: '#fdf8f3',
              100: '#f6ede1',
              200: '#ead6ba',
              300: '#dfc19a',
              400: '#d2aa79',
              500: '#b88d58',
              600: '#a17546',
              700: '#835b36',
              800: '#6b492c',
              900: '#5a3e26',
              950: '#2f1f13',
            },
            accent: {
              50: '#f2faf6',
              100: '#d9f0e5',
              200: '#b4dfcb',
              300: '#89caa9',
              400: '#61b48a',
              500: '#3c976d',
              600: '#2e7755',
              700: '#265c44',
              800: '#204b38',
              900: '#1b3e30',
              950: '#0e221b',
            },
          },
          fontFamily: {
            sans: ['Noto Sans SC', 'sans-serif'],
          },
        }
      }
  </script>
  <style>
    /* 自定义滚动条 */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: #f1f5f9;
      border-radius: 10px;
    }
    ::-webkit-scrollbar-thumb {
      background: #cbd5e1;
      border-radius: 10px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: #94a3b8;
    }
    
    /* 卡片悬停效果 */
    .site-card {
      transition: transform 0.2s ease, box-shadow 0.2s ease;
      position: relative;
    }
    .site-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
    
    /* 卡片描述悬停显示 */
    .site-card .description {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      background: rgba(0, 0, 0, 0.8);
      color: white;
      padding: 8px;
      border-radius: 0 0 6px 6px;
      transform: translateY(100%);
      transition: transform 0.2s ease;
      z-index: 10;
      font-size: 12px;
    }
    .site-card:hover .description {
      transform: translateY(0);
    }
    
    /* 复制成功提示动画 */
    @keyframes fadeInOut {
      0% { opacity: 0; transform: translateY(10px); }
      20% { opacity: 1; transform: translateY(0); }
      80% { opacity: 1; transform: translateY(0); }
      100% { opacity: 0; transform: translateY(-10px); }
    }
    .copy-success-animation {
      animation: fadeInOut 2s ease forwards;
    }
    
    /* 移动端侧边栏 */
    @media (max-width: 768px) {
      .mobile-sidebar {
        transform: translateX(-100%);
        transition: transform 0.3s ease;
      }
      .mobile-sidebar.open {
        transform: translateX(0);
      }
      .mobile-overlay {
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.3s ease;
      }
      .mobile-overlay.open {
        opacity: 1;
        pointer-events: auto;
      }
    }
    
    /* 搜索引擎下拉菜单 */
    .search-engine-dropdown {
      position: relative;
    }
    .search-engine-menu {
      position: absolute;
      top: 100%;
      right: 0;
      background: white;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      z-index: 50;
      min-width: 150px;
      display: none;
    }
    .search-engine-menu.show {
      display: block;
    }
    .search-engine-option {
      padding: 8px 12px;
      cursor: pointer;
      transition: background-color 0.2s;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .search-engine-option:hover {
      background-color: #f1f5f9;
    }
    .search-engine-option.active {
      background-color: #e1e7f1;
      font-weight: 500;
    }
    
    /* 网站预览弹窗 */
    .preview-modal {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.3s, visibility 0.3s;
    }
    .preview-modal.show {
      opacity: 1;
      visibility: visible;
    }
    .preview-content {
      background: white;
      border-radius: 12px;
      width: 90%;
      max-width: 800px;
      height: 80%;
      display: flex;
      flex-direction: column;
      transform: scale(0.9);
      transition: transform 0.3s;
    }
    .preview-modal.show .preview-content {
      transform: scale(1);
    }
    .preview-header {
      padding: 16px;
      border-bottom: 1px solid #e1e7f1;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .preview-body {
      flex: 1;
      padding: 0;
      overflow: hidden;
    }
    .preview-iframe {
      width: 100%;
      height: 100%;
      border: none;
    }
    
    /* 图片懒加载 */
    .lazy-image {
      opacity: 0;
      transition: opacity 0.3s;
    }
    .lazy-image.loaded {
      opacity: 1;
    }
    
    /* 拖拽排序 */
    .sortable-ghost {
      opacity: 0.4;
      background-color: #f0f8ff;
    }
    .sortable-drag {
      opacity: 0.9;
    }
    
    /* 侧边栏控制 */
    #sidebar-toggle {
      display: none;
    }
    
    @media (min-width: 769px) {
      #sidebar-toggle:checked ~ .sidebar {
        margin-left: -16rem;
      }
      #sidebar-toggle:checked ~ .main-content {
        margin-left: 0;
      }
    }
  </style>
</head>
<body class="bg-slate-50 font-sans text-gray-800">
  <!-- 侧边栏开关 -->
  <input type="checkbox" id="sidebar-toggle" class="hidden">
  
  <!-- 移动端导航按钮 -->
  <div class="fixed top-4 left-4 z-50 lg:hidden">
    <button id="sidebarToggle" class="p-2 rounded-lg bg-white shadow-md hover:bg-gray-100">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </button>
  </div>
  
  <!-- 移动端遮罩层 -->
  <div id="mobileOverlay" class="fixed inset-0 bg-black bg-opacity-50 z-40 mobile-overlay lg:hidden"></div>
  
  <!-- 桌面侧边栏开关按钮 -->
  <div class="fixed top-4 left-4 z-50 hidden lg:block">
    <label for="sidebar-toggle" class="p-2 rounded-lg bg-white shadow-md hover:bg-gray-100 inline-block cursor-pointer">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </label>
  </div>
  
  <!-- 侧边栏导航 -->
  <aside id="sidebar" class="sidebar fixed left-0 top-0 h-full w-64 bg-white shadow-md border-r border-slate-200 z-50 overflow-y-auto mobile-sidebar lg:transform-none transition-all duration-300">
    <div class="p-6">
      <div class="flex items-center justify-between mb-8">
        <h2 class="text-2xl font-bold text-primary-600 tracking-tight">精灵导航网</h2>
        <button id="closeSidebar" class="p-1 rounded-full hover:bg-gray-100 lg:hidden">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
        <label for="sidebar-toggle" class="p-1 rounded-full hover:bg-gray-100 hidden lg:block cursor-pointer">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </label>
      </div>
      
      <div class="mb-6">
        <div class="relative">
          <input id="searchInput" type="text" placeholder="搜索书签..." class="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400 transition">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-400 absolute left-3 top-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>
      
      <div>
        <h3 class="text-sm font-medium text-gray-500 uppercase tracking-wider mb-3">分类导航</h3>
        <div class="space-y-1">
          <a href="?" class="flex items-center px-3 py-2 rounded-lg ${catalogExists ? 'hover:bg-gray-100' : 'bg-slate-100 text-primary-700'} w-full">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2 ${catalogExists ? 'text-gray-400' : 'text-primary-600'}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            全部
          </a>
          ${catalogLinkMarkup}
        </div>
      </div>
      
      <div class="mt-6">
        <h3 class="text-sm font-medium text-gray-500 uppercase tracking-wider mb-3">热门标签</h3>
        <div class="flex flex-wrap gap-2">
          ${allTags.slice(0, 8).map(tag => `
            <a href="?tag=${encodeURIComponent(tag)}" class="inline-block px-2 py-1 bg-primary-100 text-primary-700 rounded-full text-xs hover:bg-primary-200">
              ${escapeHTML(tag)}
            </a>
          `).join('')}
          ${allTags.length > 8 ? `
            <button onclick="showAllTags()" class="text-xs text-gray-500 hover:text-gray-700">
              更多...
            </button>
          ` : ''}
        </div>
      </div>
      
      <div class="mt-8 pt-6 border-t border-gray-200">
        ${submissionEnabled ? `
        <button id="addSiteBtnSidebar" class="w-full flex items-center justify-center px-4 py-2 bg-accent-500 text-white rounded-lg hover:bg-accent-600 transition duration-300">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          添加新书签
        </button>` : `
        <div class="w-full px-4 py-3 text-xs text-primary-600 bg-white border border-slate-200 rounded-lg">
          访客书签提交功能已关闭
        </div>`}
        
        <a href="https://www.wangwangit.com/" target="_blank" class="mt-4 flex items-center px-4 py-2 text-gray-600 hover:text-primary-500 transition duration-300">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
          </svg>
          访问博客
        </a>

        <a href="/admin" target="_blank" class="mt-4 flex items-center px-4 py-2 text-gray-600 hover:text-primary-500 transition duration-300">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-1.065-2.573c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          后台管理
        </a>
      </div>
    </div>
  </aside>
  
  <!-- 主内容区 -->
  <main class="main-content lg:ml-64 min-h-screen transition-all duration-300">
    <!-- 搜索区域 -->
    <header class="bg-white shadow-sm p-4 sticky top-0 z-10">
      <div class="max-w-4xl mx-auto flex items-center justify-between gap-4">
        <!-- 左侧：标题和统计 -->
        <div class="flex items-center gap-4">
          <h1 class="text-xl font-bold flex items-center gap-2">
            <span id="categoryTitle">${titleText}</span>
            <span class="text-sm font-normal text-gray-500">(<span id="siteCount">${titleCount}</span>)</span>
          </h1>
        </div>
        
        <!-- 右侧：拖拽排序 -->
        <div class="flex items-center gap-2">
          <button id="enableDragSort" class="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <span class="text-sm text-gray-500">拖拽排序</span>
        </div>
      </div>
      
      <!-- 搜索框 -->
      <div class="max-w-2xl mx-auto w-full">
        <div class="relative">
          <input id="mainSearchInput" type="text" placeholder="搜索..." 
                 class="w-full px-4 py-2 pr-24 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent">
          <div class="absolute right-0 top-0 h-full flex items-center">
            <!-- 搜索引擎选择按钮 -->
            <div class="search-engine-dropdown">
              <button id="searchEngineBtn" class="px-3 py-2 h-full flex items-center gap-1 text-sm bg-gray-100 hover:bg-gray-200 rounded-r-lg transition-colors">
                <span id="currentEngine">站内</span>
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              <div id="searchEngineMenu" class="search-engine-menu">
                <div class="search-engine-option active" data-engine="site">
                  <i class="fas fa-search"></i>
                  <span>站内搜索</span>
                </div>
                <div class="search-engine-option" data-engine="google">
                  <i class="fab fa-google"></i>
                  <span>Google</span>
                </div>
                <div class="search-engine-option" data-engine="baidu">
                  <i class="fas fa-paw"></i>
                  <span>百度</span>
                </div>
                <div class="search-engine-option" data-engine="bing">
                  <i class="fab fa-microsoft"></i>
                  <span>Bing</span>
                </div>
                <div class="search-engine-option" data-engine="github">
                  <i class="fab fa-github"></i>
                  <span>GitHub</span>
                </div>
              </div>
            </div>
            <!-- 搜索按钮 -->
            <button id="searchButton" class="ml-1 px-3 py-2 h-full bg-primary-500 text-white rounded-r-lg hover:bg-primary-600 transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </header>
    
    <!-- 网站列表 -->
    <section class="max-w-7xl mx-auto px-4 sm:px-6 py-8">
      <div class="rounded-2xl border border-slate-200 bg-white p-4 sm:p-6 shadow-sm">
        <div id="sitesGrid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4">
          ${currentSites.map((site) => {
            const rawName = site.name || '未命名';
            const rawCatalog = site.catelog || '未分类';
            const rawDesc = site.desc || '暂无描述';
            const normalizedUrl = sanitizeUrl(site.url);
            const hrefValue = escapeHTML(normalizedUrl || '#');
            const dataUrlAttr = escapeHTML(normalizedUrl || '');
            const logoUrl = sanitizeUrl(site.logo);
            const cardInitial = escapeHTML((rawName.trim().charAt(0) || '站').toUpperCase());
            const safeName = escapeHTML(rawName);
            const safeDesc = escapeHTML(rawDesc);
            const safeDataName = escapeHTML(site.name || '');
            const safeDataCatalog = escapeHTML(site.catelog || '');
            const hasValidUrl = Boolean(normalizedUrl);
            
            // 优化：使用Google S2服务获取Favicon
            let faviconUrl = '';
            if (site.url) {
              try {
                const urlObj = new URL(site.url);
                faviconUrl = `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=64`;
              } catch (e) {
                faviconUrl = '';
              }
            }
            
            // 优先使用自定义logo，其次使用favicon，最后使用随机SVG
            let displayLogo = '';
            if (logoUrl) {
              displayLogo = `<img src="${escapeHTML(logoUrl)}" alt="${safeName}" class="w-12 h-12 rounded object-cover lazy-image" data-src="${escapeHTML(logoUrl)}" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                   <div class="w-12 h-12 rounded-lg bg-primary-600 flex items-center justify-center text-white font-semibold text-lg shadow-inner" style="display:none;">${cardInitial}</div>`;
            } else if (faviconUrl) {
              displayLogo = `<img src="${escapeHTML(faviconUrl)}" alt="${safeName}" class="w-12 h-12 rounded object-cover lazy-image" data-src="${escapeHTML(faviconUrl)}" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                   <div class="w-12 h-12 rounded-lg bg-primary-600 flex items-center justify-center text-white font-semibold text-lg shadow-inner" style="display:none;">${cardInitial}</div>`;
            } else {
              displayLogo = `<div class="w-12 h-12 rounded-lg bg-primary-600 flex items-center justify-center text-white font-semibold text-lg shadow-inner">${cardInitial}</div>`;
            }
            
            return `
              <div class="site-card bg-white border border-slate-200 rounded-lg shadow-sm hover:shadow-md transition-all duration-200 overflow-hidden flex flex-col items-center justify-center p-4 h-32" data-id="${site.id}" data-name="${safeDataName}" data-url="${dataUrlAttr}" data-catalog="${safeDataCatalog}">
                <a href="${hrefValue}" ${hasValidUrl ? 'target="_blank" rel="noopener noreferrer"' : ''} class="flex flex-col items-center justify-center w-full h-full">
                  <div class="w-12 h-12 mb-2 flex items-center justify-center">
                    ${displayLogo}
                  </div>
                  <h3 class="text-sm font-medium text-gray-900 text-center truncate w-full" title="${safeName}">${safeName}</h3>
                </a>
                <div class="description text-xs text-center">${safeDesc}</div>
                <div class="preview-btn absolute top-2 right-2 bg-white bg-opacity-80 rounded-full p-1 opacity-0 hover:opacity-100 transition-opacity cursor-pointer" data-url="${dataUrlAttr}">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    </section>
  </main>
  
  <!-- 网站预览弹窗 -->
  <div id="previewModal" class="preview-modal">
    <div class="preview-content">
      <div class="preview-header">
        <h3 id="previewTitle" class="text-lg font-medium">网站预览</h3>
        <button id="closePreview" class="p-1 rounded-full hover:bg-gray-100">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
      <div class="preview-body">
        <iframe id="previewIframe" class="preview-iframe" src="" sandbox="allow-same-origin allow-scripts allow-forms"></iframe>
      </div>
    </div>
  </div>
  
  ${submissionEnabled ? `
  <!-- 添加网站模态框 -->
  <div id="addSiteModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 opacity-0 invisible transition-all duration-300">
    <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4 transform translate-y-8 transition-all duration-300">
      <div class="p-6">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-xl font-semibold text-gray-900">添加新书签</h2>
          <button id="closeModal" class="text-gray-400 hover:text-gray-500">
            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <form id="addSiteForm" class="space-y-4">
          <div>
            <label for="addSiteName" class="block text-sm font-medium text-gray-700">名称</label>
            <input type="text" id="addSiteName" required class="mt-1 block w-full px-3 py-2 border border-slate-200 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400">
          </div>
          
          <div>
            <label for="addSiteUrl" class="block text-sm font-medium text-gray-700">网址</label>
            <input type="text" id="addSiteUrl" required class="mt-1 block w-full px-3 py-2 border border-slate-200 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400">
          </div>
          
          <div>
            <label for="addSiteLogo" class="block text-sm font-medium text-gray-700">Logo (可选)</label>
            <input type="text" id="addSiteLogo" class="mt-1 block w-full px-3 py-2 border border-slate-200 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400">
          </div>
          
          <div>
            <label for="addSiteDesc" class="block text-sm font-medium text-gray-700">描述 (可选)</label>
            <textarea id="addSiteDesc" rows="2" class="mt-1 block w-full px-3 py-2 border border-slate-200 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400"></textarea>
          </div>
          
          <div>
            <label for="addSiteCatelog" class="block text-sm font-medium text-gray-700">分类</label>
            <input type="text" id="addSiteCatelog" required class="mt-1 block w-full px-3 py-2 border border-slate-200 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400" list="catalogList">
            <datalist id="catalogList">
              ${datalistOptions}
            </datalist>
          </div>
          
          <div>
            <label for="addSiteTags" class="block text-sm font-medium text-gray-700">标签 (逗号分隔)</label>
            <input type="text" id="addSiteTags" class="mt-1 block w-full px-3 py-2 border border-slate-200 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-200 focus:border-primary-400">
          </div>
          
          <div class="flex justify-end pt-4">
            <button type="button" id="cancelAddSite" class="bg-white py-2 px-4 border border-slate-200 rounded-md shadow-sm text-sm font-medium text-primary-600 hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-200 mr-3">
              取消
            </button>
            <button type="submit" class="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-accent-500 hover:bg-accent-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-accent-400">
              提交
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
  ` : ''}
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // 侧边栏控制
      const sidebar = document.getElementById('sidebar');
      const mobileOverlay = document.getElementById('mobileOverlay');
      const sidebarToggle = document.getElementById('sidebarToggle');
      const closeSidebar = document.getElementById('closeSidebar');
      
      function openSidebar() {
        sidebar.classList.add('open');
        mobileOverlay.classList.add('open');
        document.body.style.overflow = 'hidden';
      }
      
      function closeSidebarMenu() {
        sidebar.classList.remove('open');
        mobileOverlay.classList.remove('open');
        document.body.style.overflow = '';
      }
      
      if (sidebarToggle) sidebarToggle.addEventListener('click', openSidebar);
      if (closeSidebar) closeSidebar.addEventListener('click', closeSidebarMenu);
      if (mobileOverlay) mobileOverlay.addEventListener('click', closeSidebarMenu);
      
      // 搜索引擎下拉菜单
      const searchEngineBtn = document.getElementById('searchEngineBtn');
      const searchEngineMenu = document.getElementById('searchEngineMenu');
      const currentEngine = document.getElementById('currentEngine');
      const searchEngineOptions = document.querySelectorAll('.search-engine-option');
      
      searchEngineBtn.addEventListener('click', function() {
        searchEngineMenu.classList.toggle('show');
      });
      
      searchEngineOptions.forEach(option => {
        option.addEventListener('click', function() {
          searchEngineOptions.forEach(opt => opt.classList.remove('active'));
          this.classList.add('active');
          currentEngine.textContent = this.querySelector('span').textContent;
          searchEngineMenu.classList.remove('show');
        });
      });
      
      // 点击外部关闭下拉菜单
      document.addEventListener('click', function(e) {
        if (!searchEngineBtn.contains(e.target) && !searchEngineMenu.contains(e.target)) {
          searchEngineMenu.classList.remove('show');
        }
      });
      
      // 搜索功能
      const mainSearchInput = document.getElementById('mainSearchInput');
      const searchButton = document.getElementById('searchButton');
      
      function performSearch() {
        const activeOption = document.querySelector('.search-engine-option.active');
        const engine = activeOption ? activeOption.dataset.engine : 'site';
        const query = mainSearchInput.value.trim();
        
        if (!query) return;
        
        switch(engine) {
          case 'google':
            window.open(\`https://www.google.com/search?q=\${encodeURIComponent(query)}\`, '_blank');
            break;
          case 'baidu':
            window.open(\`https://www.baidu.com/s?wd=\${encodeURIComponent(query)}\`, '_blank');
            break;
          case 'bing':
            window.open(\`https://www.bing.com/search?q=\${encodeURIComponent(query)}\`, '_blank');
            break;
          case 'github':
            window.open(\`https://github.com/search?q=\${encodeURIComponent(query)}\`, '_blank');
            break;
          default:
            // 站内搜索
            const url = new URL(window.location);
            url.searchParams.set('keyword', query);
            url.searchParams.delete('catalog');
            url.searchParams.delete('tag');
            window.location.href = url.toString();
        }
      }
      
      if (searchButton) {
        searchButton.addEventListener('click', performSearch);
      }
      
      if (mainSearchInput) {
        mainSearchInput.addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            performSearch();
          }
        });
      }
      
      // 站内搜索功能
      const searchInput = document.getElementById('searchInput');
      const sitesGrid = document.getElementById('sitesGrid');
      
      if (searchInput && sitesGrid) {
        searchInput.addEventListener('input', function() {
          const keyword = this.value.toLowerCase().trim();
          const siteCards = sitesGrid.querySelectorAll('.site-card');
          
          siteCards.forEach(card => {
            const name = (card.getAttribute('data-name') || '').toLowerCase();
            const url = (card.getAttribute('data-url') || '').toLowerCase();
            const catalogValue = (card.getAttribute('data-catalog') || '').toLowerCase();
            
            if (name.includes(keyword) || url.includes(keyword) || catalogValue.includes(keyword)) {
              card.classList.remove('hidden');
            } else {
              card.classList.add('hidden');
            }
          });
          
          // 更新计数
          const visibleCards = sitesGrid.querySelectorAll('.site-card:not(.hidden)');
          const siteCount = document.getElementById('siteCount');
          if (siteCount) {
            siteCount.textContent = visibleCards.length;
          }
        });
      }
      
      // 网站预览功能
      const previewModal = document.getElementById('previewModal');
      const previewIframe = document.getElementById('previewIframe');
      const previewTitle = document.getElementById('previewTitle');
      const closePreview = document.getElementById('closePreview');
      
      // 为所有预览按钮添加事件
      document.addEventListener('click', function(e) {
        if (e.target.closest('.preview-btn')) {
          const btn = e.target.closest('.preview-btn');
          const url = btn.getAttribute('data-url');
          const siteName = btn.closest('.site-card').getAttribute('data-name');
          
          if (url && url !== '#') {
            previewTitle.textContent = \`预览: \${siteName}\`;
            previewIframe.src = url;
            previewModal.classList.add('show');
          }
        }
      });
      
      if (closePreview) {
        closePreview.addEventListener('click', function() {
          previewModal.classList.remove('show');
          previewIframe.src = '';
        });
      }
      
      previewModal.addEventListener('click', function(e) {
        if (e.target === previewModal) {
          previewModal.classList.remove('show');
          previewIframe.src = '';
        }
      });
      
      // 图片懒加载
      const lazyImages = document.querySelectorAll('.lazy-image');
      const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const img = entry.target;
            img.src = img.dataset.src;
            img.classList.add('loaded');
            observer.unobserve(img);
          }
        });
      });
      
      lazyImages.forEach(img => imageObserver.observe(img));
      
      // 拖拽排序功能
      let sortableInstance = null;
      const enableDragSort = document.getElementById('enableDragSort');
      const sitesGridContainer = document.getElementById('sitesGrid');
      
      // 从localStorage读取排序
      function loadCustomOrder() {
        const customOrder = localStorage.getItem('siteCustomOrder');
        if (customOrder) {
          try {
            const orderData = JSON.parse(customOrder);
            const siteCards = Array.from(sitesGridContainer.querySelectorAll('.site-card'));
            
            // 按照保存的顺序重新排列卡片
            orderData.forEach(id => {
              const card = siteCards.find(c => c.getAttribute('data-id') === id);
              if (card) {
                sitesGridContainer.appendChild(card);
              }
            });
          } catch (e) {
            console.error('Failed to load custom order:', e);
          }
        }
      }
      
      // 保存排序到localStorage
      function saveCustomOrder() {
        const siteCards = Array.from(sitesGridContainer.querySelectorAll('.site-card'));
        const orderData = siteCards.map(card => card.getAttribute('data-id'));
        localStorage.setItem('siteCustomOrder', JSON.stringify(orderData));
      }
      
      if (enableDragSort && sitesGridContainer) {
        enableDragSort.addEventListener('click', function() {
          if (sortableInstance) {
            sortableInstance.destroy();
            sortableInstance = null;
            this.classList.remove('bg-primary-500', 'text-white');
            this.classList.add('bg-gray-100');
          } else {
            sortableInstance = new Sortable(sitesGridContainer, {
              animation: 150,
              ghostClass: 'sortable-ghost',
              dragClass: 'sortable-drag',
              onEnd: function(evt) {
                saveCustomOrder();
              }
            });
            this.classList.remove('bg-gray-100');
            this.classList.add('bg-primary-500', 'text-white');
          }
        });
      }
      
      // 页面加载时应用自定义排序
      setTimeout(() => {
        loadCustomOrder();
      }, 100);
      
      ${submissionEnabled ? `
      // 添加网站模态框
      const addSiteModal = document.getElementById('addSiteModal');
      const addSiteBtnSidebar = document.getElementById('addSiteBtnSidebar');
      const closeModalBtn = document.getElementById('closeModal');
      const cancelAddSite = document.getElementById('cancelAddSite');
      const addSiteForm = document.getElementById('addSiteForm');
      
      function openModal() {
        if (addSiteModal) {
          addSiteModal.classList.remove('opacity-0', 'invisible');
          const modalContent = addSiteModal.querySelector('.max-w-md');
          if (modalContent) modalContent.classList.remove('translate-y-8');
          document.body.style.overflow = 'hidden';
        }
      }
      
      function closeModal() {
        if (addSiteModal) {
          addSiteModal.classList.add('opacity-0', 'invisible');
          const modalContent = addSiteModal.querySelector('.max-w-md');
          if (modalContent) modalContent.classList.add('translate-y-8');
          document.body.style.overflow = '';
        }
      }
      
      if (addSiteBtnSidebar) {
        addSiteBtnSidebar.addEventListener('click', function(e) {
          e.preventDefault();
          e.stopPropagation();
          openModal();
        });
      }
      
      if (closeModalBtn) {
        closeModalBtn.addEventListener('click', closeModal);
      }
      
      if (cancelAddSite) {
        cancelAddSite.addEventListener('click', closeModal);
      }
      
      if (addSiteModal) {
        addSiteModal.addEventListener('click', function(e) {
          if (e.target === addSiteModal) {
            closeModal();
          }
        });
      }
      
      // 表单提交处理
      if (addSiteForm) {
        addSiteForm.addEventListener('submit', function(e) {
          e.preventDefault();
          
          const name = document.getElementById('addSiteName').value;
          const url = document.getElementById('addSiteUrl').value;
          const logo = document.getElementById('addSiteLogo').value;
          const desc = document.getElementById('addSiteDesc').value;
          const catelog = document.getElementById('addSiteCatelog').value;
          const tags = document.getElementById('addSiteTags').value;
          
          fetch('/api/config/submit', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, url, logo, desc, catelog, tags })
          })
          .then(res => res.json())
          .then(data => {
            if (data.code === 201) {
              // 显示成功消息
              const successDiv = document.createElement('div');
              successDiv.className = 'fixed top-4 right-4 bg-accent-500 text-white px-4 py-2 rounded shadow-lg z-50';
              successDiv.textContent = '提交成功，等待管理员审核';
              document.body.appendChild(successDiv);
              
              setTimeout(() => {
                successDiv.classList.add('opacity-0');
                setTimeout(() => {
                  if (document.body.contains(successDiv)) {
                    document.body.removeChild(successDiv);
                  }
                }, 300);
              }, 2500);
              
              closeModal();
              addSiteForm.reset();
            } else {
              alert(data.message || '提交失败');
            }
          })
          .catch(err => {
            console.error('网络错误:', err);
            alert('网络错误，请稍后重试');
          });
        });
      }
      ` : ''}
    });
  </script>
</body>
</html>`;

  // 添加缓存头
  const response = new Response(html, {
    headers: { 
      'content-type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600' 
    }
  });
  return response;
}

// ========== 主入口 ==========
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    if (url.pathname.startsWith('/api')) {
      return api.handleRequest(request, env, ctx);
    } else if (url.pathname === '/admin' || url.pathname.startsWith('/static')) {
      return admin.handleRequest(request, env, ctx);
    } else {
      return handleRequest(request, env, ctx);
    }
  },
};
