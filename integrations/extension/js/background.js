const BNVD_API = 'https://bnvd.org/api/v1';

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'bnvd-lookup',
    title: 'Buscar no BNVD',
    contexts: ['selection']
  });
  
  chrome.contextMenus.create({
    id: 'bnvd-kev-check',
    title: 'Verificar no KEV',
    contexts: ['selection']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const selectedText = info.selectionText?.trim().toUpperCase();
  
  if (!selectedText) return;
  
  const cveMatch = selectedText.match(/CVE-\d{4}-\d{4,}/);
  const cveId = cveMatch ? cveMatch[0] : selectedText.startsWith('CVE-') ? selectedText : null;
  
  if (!cveId) {
    chrome.tabs.sendMessage(tab.id, {
      type: 'BNVD_NOTIFICATION',
      message: 'Selecione um CVE valido (ex: CVE-2024-12345)'
    });
    return;
  }
  
  if (info.menuItemId === 'bnvd-lookup') {
    chrome.tabs.create({
      url: `https://bnvd.org/vulnerabilidade/${cveId}`
    });
  } else if (info.menuItemId === 'bnvd-kev-check') {
    try {
      // Ajustado para usar o endpoint correto de detalhes que contém flags de KEV
      const response = await fetch(`${BNVD_API}/vulnerabilities/${cveId}`);
      const data = await response.json();
      const cveData = data.data || {};
      
      chrome.tabs.sendMessage(tab.id, {
        type: 'BNVD_KEV_RESULT',
        cveId,
        inKev: cveData.is_kev || false,
        kevData: cveData.kev_data || null
      });
    } catch (error) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'BNVD_NOTIFICATION',
        message: `Erro ao verificar KEV: ${error.message}`
      });
    }
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'BNVD_API_REQUEST') {
    fetch(`${BNVD_API}${request.endpoint}`)
      .then(response => response.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});
