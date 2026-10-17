"""
core/auditor.py
Core security engine for evaluating HTTP response headers and cookie security flags.
"""

from typing import Dict, Any, List, Optional
import json
from datetime import datetime
import requests
from utils.logger import ConsoleLogger


class SecurityAuditor:
    MANDATORY_HEADERS: Dict[str, str] = {
        "Strict-Transport-Security": "Protects against SSL stripping and man-in-the-middle attacks.",
        "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection vectors.",
        "X-Frame-Options": "Defends against clickjacking (UI redress) attacks.",
        "X-Content-Type-Options": "Prevents MIME-type sniffing vulnerabilities.",
        "Referrer-Policy": "Controls privacy leakage across origin requests.",
        "Permissions-Policy": "Restricts browser hardware access (e.g., camera, microphone, geolocation)."
    }

    def __init__(self, target_url: str, timeout: int = 10, output_file: Optional[str] = None) -> None:
        if not target_url.startswith(("http://", "https://")):
            self.target_url = f"https://{target_url}"
        else:
            self.target_url = target_url
        self.timeout = timeout
        self.output_file = output_file

    def audit(self) -> Dict[str, Any]:
        """Performs network analysis and returns structured audit results."""
        ConsoleLogger.header("HTTP Security Headers & Cookie Audit Engine")
        ConsoleLogger.info(f"Target URL: {self.target_url}")

        try:
            response = requests.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "SecOps-Auditor/1.0"}
            )
        except requests.exceptions.RequestException as err:
            ConsoleLogger.failure(f"Connection failed: {err}")
            return {}

        ConsoleLogger.info(f"HTTP Status Code : {response.status_code}")
        ConsoleLogger.info(f"Final Endpoint   : {response.url}\n")

        # 1. Header Evaluation
        ConsoleLogger.info("Evaluating Transport & Application Security Headers...")
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        passed_headers: Dict[str, str] = {}
        missing_headers: Dict[str, str] = {}

        for header, description in self.MANDATORY_HEADERS.items():
            if header.lower() in headers_lower:
                val = headers_lower[header.lower()]
                passed_headers[header] = val
                ConsoleLogger.success(f"{header}: {val}")
            else:
                missing_headers[header] = description
                ConsoleLogger.failure(f"{header} is missing!")
                ConsoleLogger.warning(f"  Risk Profile: {description}")

        # 2. Cookie Evaluation
        print()
        ConsoleLogger.info("Evaluating Cookie Security Flags...")
        cookie_records = []
        if not response.cookies:
            ConsoleLogger.info("No Set-Cookie attributes detected on the baseline response.")
        else:
            for cookie in response.cookies:
                flags = []
                is_secure = cookie.secure
                is_httponly = (
                    cookie.has_nonstandard_attr('httponly') or 
                    cookie.has_nonstandard_attr('HttpOnly')
                )
                samesite = cookie._rest.get('SameSite', 'Not-Set')

                flags.append(f"Secure={is_secure}")
                flags.append(f"HttpOnly={is_httponly}")
                flags.append(f"SameSite={samesite}")

                if is_secure and is_httponly:
                    ConsoleLogger.success(f"Cookie '{cookie.name}': {', '.join(flags)}")
                else:
                    ConsoleLogger.warning(f"Insecure Cookie Configuration '{cookie.name}': {', '.join(flags)}")

                cookie_records.append({
                    "name": cookie.name,
                    "secure": is_secure,
                    "httponly": is_httponly,
                    "samesite": samesite
                })

        # 3. Compliance Metric
        total = len(self.MANDATORY_HEADERS)
        passed_count = len(passed_headers)
        compliance_pct = int((passed_count / total) * 100)

        print()
        ConsoleLogger.info("Compliance Summary:")
        score_msg = f"Security Posture Score: {passed_count}/{total} ({compliance_pct}% Compliant)"
        if compliance_pct >= 80:
            ConsoleLogger.success(score_msg)
        else:
            ConsoleLogger.warning(score_msg)

        report_data = {
            "target": self.target_url,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "status_code": response.status_code,
            "compliance_score": {
                "passed": passed_count,
                "total": total,
                "percentage": compliance_pct
            },
            "security_headers": {
                "present": passed_headers,
                "missing": missing_headers
            },
            "cookies": cookie_records
        }

        # 4. JSON Export
        if self.output_file:
            try:
                with open(self.output_file, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=4)
                print()
                ConsoleLogger.success(f"Audit report exported successfully to: {self.output_file}")
            except OSError as e:
                ConsoleLogger.failure(f"Failed to write report file: {e}")

        return report_data