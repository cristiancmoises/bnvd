(function() {
  'use strict';
  
  function createNotification(message, type = 'info') {
    const existing = document.getElementById('bnvd-notification');
    if (existing) existing.remove();
    
    const notification = document.createElement('div');
    notification.id = 'bnvd-notification';
    notification.className = `bnvd-notification bnvd-${type}`;
    notification.innerHTML = `
      <div class="bnvd-notification-content">
        <span class="bnvd-notification-icon">${type === 'warning' ? '⚠️' : 'ℹ️'}</span>
        <span class="bnvd-notification-text">${message}</span>
        <button class="bnvd-notification-close">&times;</button>
      </div>
    `;
    
    document.body.appendChild(notification);
    
    notification.querySelector('.bnvd-notification-close').addEventListener('click', () => {
      notification.remove();
    });
    
    setTimeout(() => {
      if (notification.parentNode) {
        notification.classList.add('bnvd-fade-out');
        setTimeout(() => notification.remove(), 300);
      }
    }, 5000);
  }
  
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'BNVD_NOTIFICATION') {
      createNotification(request.message, 'info');
    } else if (request.type === 'BNVD_KEV_RESULT') {
      if (request.inKev) {
        const kev = request.kevData || {};
        createNotification(
          `<strong>${request.cveId}</strong> esta no catalogo KEV!<br>
           Vendor: ${kev.vendorProject || 'N/A'}<br>
           Prazo: ${kev.dueDate || 'N/A'}`,
          'warning'
        );
      } else {
        createNotification(
          `<strong>${request.cveId}</strong> NAO esta no catalogo KEV.`,
          'info'
        );
      }
    }
    return true;
  });
  
  function highlightCVEs() {
    const textNodes = [];
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );
    
    let node;
    while (node = walker.nextNode()) {
      if (node.parentNode.tagName !== 'SCRIPT' && 
          node.parentNode.tagName !== 'STYLE' &&
          !node.parentNode.classList.contains('bnvd-highlighted')) {
        if (/CVE-\d{4}-\d{4,}/i.test(node.textContent)) {
          textNodes.push(node);
        }
      }
    }
    
    textNodes.slice(0, 50).forEach(textNode => {
      const html = textNode.textContent.replace(
        /(CVE-\d{4}-\d{4,})/gi,
        '<a href="https://bnvd.org/vulnerabilidade/$1" target="_blank" class="bnvd-cve-link bnvd-highlighted">$1</a>'
      );
      
      if (html !== textNode.textContent) {
        const span = document.createElement('span');
        span.innerHTML = html;
        span.classList.add('bnvd-highlighted');
        textNode.parentNode.replaceChild(span, textNode);
      }
    });
  }
  
  chrome.storage.sync.get(['highlightCVEs'], (result) => {
    if (result.highlightCVEs !== false) {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', highlightCVEs);
      } else {
        highlightCVEs();
      }
    }
  });
})();
