#!/usr/bin/env python3
"""
BNVD GitHub Integration
Integração com GitHub Code Scanning e Dependabot APIs

Funcionalidades:
- Buscar alertas de Code Scanning
- Buscar alertas de Dependabot
- Correlacionar vulnerabilidades com BNVD/KEV/MITRE
- Gerar relatórios enriquecidos em português
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any

try:
    import requests
except ImportError:
    print("Erro: requests library não instalada")
    exit(1)

GITHUB_API_URL = "https://api.github.com"
BNVD_API_URL = os.environ.get('BNVD_API_URL', 'https://bnvd.org/api/v1')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GitHubClient:
    def __init__(self, token: str):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'BNVD-GitHub-Integration/1.0'
        })
    
    def get_dependabot_alerts(self, owner: str, repo: str, state: str = 'open', per_page: int = 100) -> List[Dict]:
        try:
            alerts = []
            page = 1
            
            while True:
                response = self.session.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/dependabot/alerts",
                    params={'state': state, 'per_page': per_page, 'page': page}
                )
                response.raise_for_status()
                
                data = response.json()
                if not data:
                    break
                
                alerts.extend(data)
                
                if len(data) < per_page:
                    break
                page += 1
            
            return alerts
        except Exception as e:
            logger.error(f"Erro ao buscar alertas Dependabot: {e}")
            return []
    
    def get_code_scanning_alerts(self, owner: str, repo: str, state: str = 'open', per_page: int = 100) -> List[Dict]:
        try:
            alerts = []
            page = 1
            
            while True:
                response = self.session.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/code-scanning/alerts",
                    params={'state': state, 'per_page': per_page, 'page': page}
                )
                response.raise_for_status()
                
                data = response.json()
                if not data:
                    break
                
                alerts.extend(data)
                
                if len(data) < per_page:
                    break
                page += 1
            
            return alerts
        except Exception as e:
            logger.error(f"Erro ao buscar alertas Code Scanning: {e}")
            return []
    
    def get_org_dependabot_alerts(self, org: str, state: str = 'open', per_page: int = 100) -> List[Dict]:
        try:
            response = self.session.get(
                f"{GITHUB_API_URL}/orgs/{org}/dependabot/alerts",
                params={'state': state, 'per_page': per_page}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Erro ao buscar alertas Dependabot da organização: {e}")
            return []

class BNVDClient:
    def __init__(self, api_url: str = BNVD_API_URL):
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BNVD-GitHub-Integration/1.0',
            'Accept': 'application/json'
        })
    
    def get_vulnerability(self, cve_id: str) -> Optional[Dict]:
        try:
            response = self.session.get(
                f"{self.api_url}/vulnerabilities/{cve_id}",
                params={'include_pt': 'true'},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Erro ao buscar CVE {cve_id}: {e}")
            return None
    
    def check_kev(self, cve_id: str) -> Optional[Dict]:
        try:
            response = self.session.get(
                f"{self.api_url}/kev/check/{cve_id}",
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Erro ao verificar KEV {cve_id}: {e}")
            return None

class BNVDGitHubIntegration:
    def __init__(self, github_token: str, bnvd_api_url: str = BNVD_API_URL):
        self.github = GitHubClient(github_token)
        self.bnvd = BNVDClient(bnvd_api_url)
    
    def enrich_alert(self, alert: Dict) -> Dict:
        cve_id = None
        
        if 'security_advisory' in alert:
            cve_id = alert['security_advisory'].get('cve_id')
        elif 'rule' in alert:
            desc = alert['rule'].get('description', '')
            import re
            match = re.search(r'CVE-\d{4}-\d{4,}', desc, re.IGNORECASE)
            if match:
                cve_id = match.group().upper()
        
        enriched = {
            'original_alert': alert,
            'cve_id': cve_id,
            'bnvd_data': None,
            'in_kev': False,
            'kev_data': None,
            'description_pt': None,
            'priority': 'normal'
        }
        
        if cve_id:
            bnvd_result = self.bnvd.get_vulnerability(cve_id)
            if bnvd_result and bnvd_result.get('status') == 'success':
                enriched['bnvd_data'] = bnvd_result.get('data')
                
                data = bnvd_result.get('data', {})
                descs_pt = data.get('descriptions_pt', [])
                if descs_pt and len(descs_pt) > 0:
                    enriched['description_pt'] = descs_pt[0].get('value')
            
            kev_result = self.bnvd.check_kev(cve_id)
            if kev_result and kev_result.get('in_kev'):
                enriched['in_kev'] = True
                enriched['kev_data'] = kev_result.get('kev_data')
                enriched['priority'] = 'critical'
                
                if kev_result.get('kev_data', {}).get('knownRansomwareCampaignUse', '').lower() == 'known':
                    enriched['priority'] = 'ransomware'
        
        return enriched
    
    def analyze_dependabot_alerts(self, owner: str, repo: str, state: str = 'open') -> Dict:
        alerts = self.github.get_dependabot_alerts(owner, repo, state)
        
        result = {
            'repository': f"{owner}/{repo}",
            'total_alerts': len(alerts),
            'alerts_in_kev': 0,
            'alerts_ransomware': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_ecosystem': {},
            'enriched_alerts': [],
            'summary_pt': '',
            'generated_at': datetime.now().isoformat()
        }
        
        for alert in alerts:
            enriched = self.enrich_alert(alert)
            result['enriched_alerts'].append(enriched)
            
            if enriched['in_kev']:
                result['alerts_in_kev'] += 1
            
            if enriched['priority'] == 'ransomware':
                result['alerts_ransomware'] += 1
            
            severity = alert.get('security_advisory', {}).get('severity', 'unknown').lower()
            if severity in result['by_severity']:
                result['by_severity'][severity] += 1
            
            ecosystem = alert.get('dependency', {}).get('package', {}).get('ecosystem', 'unknown')
            result['by_ecosystem'][ecosystem] = result['by_ecosystem'].get(ecosystem, 0) + 1
        
        result['summary_pt'] = self._generate_summary_pt(result)
        
        return result
    
    def analyze_code_scanning_alerts(self, owner: str, repo: str, state: str = 'open') -> Dict:
        alerts = self.github.get_code_scanning_alerts(owner, repo, state)
        
        result = {
            'repository': f"{owner}/{repo}",
            'total_alerts': len(alerts),
            'by_severity': {'error': 0, 'warning': 0, 'note': 0},
            'by_tool': {},
            'enriched_alerts': [],
            'summary_pt': '',
            'generated_at': datetime.now().isoformat()
        }
        
        for alert in alerts:
            enriched = self.enrich_alert(alert)
            result['enriched_alerts'].append(enriched)
            
            severity = alert.get('rule', {}).get('severity', 'unknown').lower()
            if severity in result['by_severity']:
                result['by_severity'][severity] += 1
            
            tool = alert.get('tool', {}).get('name', 'unknown')
            result['by_tool'][tool] = result['by_tool'].get(tool, 0) + 1
        
        return result
    
    def _generate_summary_pt(self, analysis: Dict) -> str:
        lines = [
            f"## Relatório de Vulnerabilidades - {analysis['repository']}",
            f"",
            f"**Gerado em:** {analysis['generated_at']}",
            f"",
            f"### Resumo",
            f"- **Total de alertas:** {analysis['total_alerts']}",
            f"- **Alertas no catálogo KEV:** {analysis['alerts_in_kev']}",
            f"- **Alertas associados a ransomware:** {analysis['alerts_ransomware']}",
            f"",
            f"### Por Severidade",
        ]
        
        for sev, count in analysis['by_severity'].items():
            lines.append(f"- {sev.upper()}: {count}")
        
        if analysis['alerts_in_kev'] > 0:
            lines.extend([
                f"",
                f"### ⚠️ ATENÇÃO: Vulnerabilidades Ativamente Exploradas",
                f"",
                f"As seguintes vulnerabilidades estão no catálogo CISA KEV e requerem ação imediata:",
                f""
            ])
            
            for alert in analysis['enriched_alerts']:
                if alert['in_kev']:
                    cve = alert['cve_id']
                    kev = alert.get('kev_data', {})
                    lines.append(f"- **{cve}**: {kev.get('vulnerabilityName', 'N/A')}")
                    lines.append(f"  - Prazo: {kev.get('dueDate', 'N/A')}")
                    lines.append(f"  - Ação requerida: {kev.get('requiredAction', 'N/A')}")
        
        return '\n'.join(lines)
    
    def export_report(self, analysis: Dict, filename: str, format: str = 'json'):
        if format == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)
        elif format == 'markdown':
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(analysis.get('summary_pt', ''))
        
        logger.info(f"Relatório exportado para: {filename}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='BNVD GitHub Integration')
    parser.add_argument('--token', required=True, help='GitHub Personal Access Token')
    parser.add_argument('--owner', required=True, help='Repository owner/organization')
    parser.add_argument('--repo', required=True, help='Repository name')
    parser.add_argument('--type', choices=['dependabot', 'code-scanning', 'both'], default='dependabot')
    parser.add_argument('--state', default='open', help='Alert state (open, dismissed, fixed)')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'markdown'], default='json')
    
    args = parser.parse_args()
    
    integration = BNVDGitHubIntegration(args.token)
    
    if args.type in ['dependabot', 'both']:
        result = integration.analyze_dependabot_alerts(args.owner, args.repo, args.state)
        
        if args.output:
            integration.export_report(result, args.output, args.format)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    
    if args.type in ['code-scanning', 'both']:
        result = integration.analyze_code_scanning_alerts(args.owner, args.repo, args.state)
        
        if args.output:
            output = args.output.replace('.json', '_code_scanning.json')
            integration.export_report(result, output, args.format)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

if __name__ == '__main__':
    main()
