
const BNVD_API = 'https://bnvd.org/api/v1';

// Estado global para paginação
const state = {
  kev: { page: 1, hasNext: false },
  mitre: { page: 1, hasNext: false },
  news: { page: 1, hasNext: false }
};

// Gerenciamento de abas
document.addEventListener('DOMContentLoaded', () => {
  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.panel');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.tab;

      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      document.getElementById(targetTab).classList.add('active');
    });
  });

  // Event listeners principais
  document.getElementById('search-btn').addEventListener('click', searchCVE);
  document.getElementById('cve-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchCVE();
  });

  document.getElementById('kev-search-btn').addEventListener('click', () => {
    state.kev.page = 1;
    searchKEV();
  });
  
  document.getElementById('mitre-search-btn').addEventListener('click', () => {
    state.mitre.page = 1;
    loadMITRE();
  });
  
  document.getElementById('news-refresh-btn').addEventListener('click', () => {
    state.news.page = 1;
    loadNews();
  });

  // Event listeners para paginação
  document.getElementById('kev-prev').addEventListener('click', () => {
    if (state.kev.page > 1) {
      state.kev.page--;
      searchKEV();
    }
  });
  document.getElementById('kev-next').addEventListener('click', () => {
    if (state.kev.hasNext) {
      state.kev.page++;
      searchKEV();
    }
  });

  document.getElementById('mitre-prev').addEventListener('click', () => {
    if (state.mitre.page > 1) {
      state.mitre.page--;
      loadMITRE();
    }
  });
  document.getElementById('mitre-next').addEventListener('click', () => {
    if (state.mitre.hasNext) {
      state.mitre.page++;
      loadMITRE();
    }
  });

  document.getElementById('news-prev').addEventListener('click', () => {
    if (state.news.page > 1) {
      state.news.page--;
      loadNews();
    }
  });
  document.getElementById('news-next').addEventListener('click', () => {
    if (state.news.hasNext) {
      state.news.page++;
      loadNews();
    }
  });

  // Carregar notícias ao abrir
  loadNews();
});

// Buscar CVE
async function searchCVE() {
  const input = document.getElementById('cve-input').value.trim().toUpperCase();
  const resultDiv = document.getElementById('search-result');

  if (!input) {
    showError(resultDiv, 'Digite um CVE válido (ex: CVE-2024-12345)');
    return;
  }

  const cveMatch = input.match(/CVE-\d{4}-\d{4,}/);
  const cveId = cveMatch ? cveMatch[0] : (input.startsWith('CVE-') ? input : `CVE-${input}`);

  showLoading(resultDiv);

  try {
    const response = await fetch(`${BNVD_API}/vulnerabilities/${cveId}?include_pt=true`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    if (data.status === 'success' && data.data) {
      displayCVE(resultDiv, data.data);
    } else {
      showError(resultDiv, `CVE ${cveId} não encontrado`);
    }
  } catch (error) {
    showError(resultDiv, `Erro: ${error.message}`);
  }
}

// Buscar KEV
async function searchKEV() {
  const vendor = document.getElementById('kev-vendor').value.trim();
  const ransomware = document.getElementById('kev-ransomware').value;
  const resultDiv = document.getElementById('kev-result');

  showLoading(resultDiv);

  try {
    let url = `${BNVD_API}/vulnerabilities?is_kev=true&page=${state.kev.page}&per_page=10&include_pt=true`;
    if (vendor) url += `&vendor=${encodeURIComponent(vendor)}`;
    if (ransomware === 'known') url += `&ransomware=true`;

    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    if (data.status === 'success' && data.data && data.data.length > 0) {
      state.kev.hasNext = data.pagination?.has_next || false;
      updatePaginationUI('kev', state.kev.page, state.kev.hasNext);
      displayKEV(resultDiv, data.data);
    } else {
      showError(resultDiv, 'Nenhuma vulnerabilidade KEV encontrada');
    }
  } catch (error) {
    showError(resultDiv, `Erro: ${error.message}`);
  }
}

// Carregar MITRE
async function loadMITRE() {
  const type = document.getElementById('mitre-type').value;
  const matrix = document.getElementById('mitre-matrix').value;
  const resultDiv = document.getElementById('mitre-result');

  showLoading(resultDiv);

  try {
    let endpoint = `/mitre/matrix/${matrix}`;
    if (type === 'techniques') endpoint = `/mitre/techniques?matrix=${matrix}`;
    else if (type === 'groups') endpoint = `/mitre/groups?matrix=${matrix}`;
    else if (type === 'mitigations') endpoint = `/mitre/mitigations?matrix=${matrix}`;

    const url = `${BNVD_API}${endpoint}${endpoint.includes('?') ? '&' : '?'}translate=true&page=${state.mitre.page}&per_page=5`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    const items = data.data || data;

    if (items && items.length > 0) {
      state.mitre.hasNext = data.pagination?.has_next || (items.length === 5);
      updatePaginationUI('mitre', state.mitre.page, state.mitre.hasNext);
      displayMITRE(resultDiv, items.slice(0, 5), type);
    } else {
      showError(resultDiv, 'Nenhum item MITRE encontrado');
    }
  } catch (error) {
    showError(resultDiv, `Erro: ${error.message}`);
  }
}

// Carregar notícias
async function loadNews() {
  const resultDiv = document.getElementById('news-result');
  showLoading(resultDiv);

  try {
    const response = await fetch(`${BNVD_API}/noticias?page=${state.news.page}&per_page=5`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    if (data.status === 'success' && data.data && data.data.length > 0) {
      state.news.hasNext = data.pagination?.has_next || false;
      updatePaginationUI('news', state.news.page, state.news.hasNext);
      displayNews(resultDiv, data.data);
    } else {
      showError(resultDiv, 'Nenhuma notícia encontrada');
    }
  } catch (error) {
    showError(resultDiv, `Erro: ${error.message}`);
  }
}

// Helper para UI de Paginação
function updatePaginationUI(prefix, page, hasNext) {
  const prevBtn = document.getElementById(`${prefix}-prev`);
  const nextBtn = document.getElementById(`${prefix}-next`);
  const pageNum = document.getElementById(`${prefix}-page-num`);

  if (prevBtn) prevBtn.disabled = (page === 1);
  if (nextBtn) nextBtn.disabled = !hasNext;
  if (pageNum) pageNum.textContent = page;
}

// Display CVE
function displayCVE(container, cve) {
  let score = 'N/A';
  let severity = 'N/A';
  
  // Pegar descrição prioritária PT
  const desc = cve.description_pt || (cve.descriptions_pt && cve.descriptions_pt.length > 0 ? cve.descriptions_pt[0].value : null) || cve.description || 'Sem descrição';

  if (cve.cvss_metrics) {
    const metrics = typeof cve.cvss_metrics === 'string' ? JSON.parse(cve.cvss_metrics) : cve.cvss_metrics;
    const v31 = metrics.cvssMetricV31 ? metrics.cvssMetricV31[0] : null;
    const v30 = metrics.cvssMetricV30 ? metrics.cvssMetricV30[0] : null;
    const v2 = metrics.cvssMetricV2 ? metrics.cvssMetricV2[0] : null;

    const data = (v31 || v30 || v2)?.cvssData;
    if (data) {
      score = data.baseScore || score;
      severity = data.baseSeverity || severity;
    }
  } else {
    score = cve.cvss_score || score;
    severity = cve.severity || severity;
  }

  container.innerHTML = `
    <div class="result-card">
      <h3>${cve.cve_id}</h3>
      <div class="badge ${getSeverityClass(severity)}">${severity}</div>
      <p><strong>Score CVSS:</strong> ${score}</p>
      <p class="description">${desc.substring(0, 300)}...</p>
      <a href="https://bnvd.org/vulnerabilidade/${cve.cve_id}" target="_blank" class="link-btn">
        Ver Detalhes Completos
      </a>
    </div>
  `;
}

// Display KEV
function displayKEV(container, items) {
  container.innerHTML = `
    <div class="result-list">
      ${items.map(item => {
        const cveId = item.cve_id || item.cveID || 'N/A';
        
        // Extrair dados do KEV (pode estar em kev_data ou direto)
        const kev = item.kev_data || item;
        const vendor = kev.vendorProject || kev.vendor || 'N/A';
        const product = kev.product || 'N/A';
        const dueDate = kev.dueDate || kev.due_date || 'N/A';
        const isRansomware = item.is_ransomware || kev.knownRansomwareCampaignUse === 'Known';

        return `
          <div class="result-card kev-item">
            <h4>${cveId}</h4>
            <p><strong>Vendor:</strong> ${vendor}</p>
            <p><strong>Produto:</strong> ${product}</p>
            <p><strong>Prazo:</strong> ${dueDate}</p>
            ${isRansomware ? '<div class="badge critical">RANSOMWARE</div>' : ''}
            <a href="https://bnvd.org/vulnerabilidade/${cveId}" target="_blank" class="link-btn small">
              Ver CVE
            </a>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

// Display MITRE com tradução PT
function displayMITRE(container, items, type) {
  container.innerHTML = `
    <div class="result-list">
      ${items.map(item => {
        const id = item.id || item.external_id || 'N/A';
        const name = item.name_pt || item.name || 'N/A';
        const desc = item.description_pt || item.description || 'Sem descrição';
        const tactics = item.tactics_pt || item.tactics || [];
        
        return `
          <div class="result-card mitre-item">
            <h4>${id}</h4>
            <p><strong>Nome:</strong><br>${name}</p>
            ${tactics.length > 0 ? `<p><strong>Táticas:</strong><br>${tactics.join(', ')}</p>` : ''}
            <p class="description"><strong>Descrição:</strong><br>${desc.substring(0, 200)}...</p>
            ${item.url || item.external_url ? `<a href="${item.url || item.external_url}" target="_blank" class="link-btn small">Ver MITRE</a>` : ''}
          </div>
        `;
      }).join('')}
    </div>
  `;
}

// Display notícias
function displayNews(container, news) {
  container.innerHTML = `
    <div class="result-list">
      ${news.map(item => `
        <div class="result-card news-item">
          <h4>${item.title || 'Sem título'}</h4>
          <p class="news-date">${item.pub_date_formatted || item.pub_date || ''}</p>
          <p class="description">${(item.description || '').substring(0, 100)}...</p>
          <button class="link-btn small" data-url="https://bnvd.org/noticia/${item.slug}">
            Ler Notícia
          </button>
        </div>
      `).join('')}
    </div>
  `;

  // Adicionar event listeners para abrir notícias
  container.querySelectorAll('.news-item .link-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.dataset.url;
      window.open(url, '_blank');
    });
  });
}

// Helpers
function showLoading(container) {
  container.innerHTML = '<div class="loading">Carregando...</div>';
}

function showError(container, message) {
  container.innerHTML = `<div class="error">${message}</div>`;
}

function getSeverityClass(severity) {
  const s = severity.toLowerCase();
  if (s.includes('critical')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('medium')) return 'medium';
  return 'low';
}
