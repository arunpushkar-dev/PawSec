#!/usr/bin/env python3
"""
PII Detector v2 - Comprehensive Privacy Data Detection

Aligned to GDPR Article 4(1) and India DPDP Act 2023.

Three-layer detection architecture:
  Layer 1: Strong-pattern regex matching (high-confidence standalone patterns)
  Layer 2: Contextual-linkage detection (keyword proximity unlocks weak patterns)
  Layer 3: Driver's licence detection — all 50 US states, context-gated

All detection is performed locally. No external API calls. No data logged.

Backward-compatible output: keeps 'detected', 'has_pii', 'count', 'risk_level'
New spec fields added: 'findings', 'contains_pii', 'start_index', 'end_index',
                       'reason', 'source', 'summary'
"""

from typing import Dict, List, Any, Optional
import re


# ---------------------------------------------------------------------------
# Placeholder / test-data suppression
# ---------------------------------------------------------------------------
_PLACEHOLDER_RE = re.compile(
    r'\b(example|sample|dummy|placeholder|test\s+data|for\s+illustration|'
    r'fake|not\s+real|fictitious|lorem\s+ipsum)\b',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Layer 2 context keyword patterns
# ---------------------------------------------------------------------------
_CTX = {
    'name': re.compile(
        r'\b(name|full\s+name|my\s+name\s+is|customer\s+name|employee\s+name|'
        r'patient\s+name|student\s+name|mr\.?|mrs\.?|ms\.?|dr\.?|prof\.?|sir|'
        r'daughter\s+of|son\s+of|wife\s+of|husband\s+of|'
        r"father'?s?\s+name|mother'?s?\s+name|guardian\s+name|spouse\s+name)\b",
        re.IGNORECASE
    ),
    'dob': re.compile(
        r'\b(dob|date\s+of\s+birth|born\s+on|birth\s+date|birthdate|'
        r'yob|year\s+of\s+birth|d\.o\.b\.?)\b',
        re.IGNORECASE
    ),
    'address': re.compile(
        r'\b(address|resides?\s+at|lives?\s+at|residence|flat\s+no?\.?|'
        r'apartment|house\s+no?\.?|plot\s+no?\.?|block|sector|street|road|'
        r'lane|village|tehsil|district|pincode|pin\s+code|postal\s+code|'
        r'zip\s+code|zip|postcode)\b',
        re.IGNORECASE
    ),
    'employee_id': re.compile(
        r'\b(employee\s+id|emp\s+id|associate\s+id|staff\s+id|'
        r'emp\.?\s*no\.?|employee\s+no\.?|emp\s+code|worker\s+id|personnel\s+id)\b',
        re.IGNORECASE
    ),
    'student_id': re.compile(
        r'\b(student\s+id|student\s+no\.?|roll\s+no\.?|roll\s+number|'
        r'admission\s+no\.?|registration\s+no\.?|enrolment\s+no\.?|scholar\s+no\.?)\b',
        re.IGNORECASE
    ),
    'customer_id': re.compile(
        r'\b(customer\s+id|customer\s+no\.?|client\s+id|user\s+id|member\s+id|'
        r'subscriber\s+id|account\s+id|crm\s+id|loyalty\s+id)\b',
        re.IGNORECASE
    ),
    'username': re.compile(
        r'\b(username|user\s+name|handle|screen\s+name|login\s+id|login|'
        r'profile\s+name|gamer\s+tag|social\s+handle|twitter\s+handle)\b',
        re.IGNORECASE
    ),
    'health': re.compile(
        r'\b(patient|diagnosis|prescribed|prescription|blood\s+group|blood\s+type|'
        r'medical\s+condition|health\s+condition|disease|disorder|syndrome|treatment|'
        r'medication|drug\s+name|dosage|allergic|allergy|disability|mental\s+health|'
        r'pregnant|pregnancy|hiv|cancer|diabetes|hypertension|tumour|tumor)\b',
        re.IGNORECASE
    ),
    'family': re.compile(
        r"\b(father'?s?\s+name|mother'?s?\s+name|spouse\s+name|wife\s+of|"
        r"husband\s+of|son\s+of|daughter\s+of|guardian\s+name|parent'?s?\s+name|"
        r'next\s+of\s+kin)\b',
        re.IGNORECASE
    ),
    'account': re.compile(
        r'\b(account\s+no\.?|a/?c\s+no\.?|bank\s+account|acct\.?\s*no\.?|'
        r'account\s+number|savings\s+account|current\s+account|'
        r'iban|ifsc|swift\s+code|routing\s+number|sort\s+code)\b',
        re.IGNORECASE
    ),
    'vehicle': re.compile(
        r'\b(license\s+plate|number\s+plate|registration\s+no\.?|'
        r'vehicle\s+no\.?|vehicle\s+registration|vin|chassis\s+no\.?|'
        r'chassis\s+number|vehicle\s+owner)\b',
        re.IGNORECASE
    ),
    'driving_licence': re.compile(
        r'\b(driving\s+licen[cs]e|dl\s+no\.?|dl\s+number|driver\s+licen[cs]e|'
        r'licence\s+no\.?)\b',
        re.IGNORECASE
    ),
    'voter': re.compile(
        r'\b(voter\s+id|voter\s+card|epic\s+no\.?|election\s+card|'
        r'elector\'?s?\s+id)\b',
        re.IGNORECASE
    ),
    'upi': re.compile(
        r'\b(upi\s+id|upi\s+handle|pay\s+to|send\s+to|upi|gpay|phonepe|paytm)\b',
        re.IGNORECASE
    ),
    'cookie': re.compile(
        r'\b(cookie|session\s+id|session\s+token|auth\s+token|sid|'
        r'advertising\s+id|aaid|idfa|android\s+id|device\s+id|tracker\s+id)\b',
        re.IGNORECASE
    ),
    'age': re.compile(
        r'\b(age|aged|years?\s+old)\b',
        re.IGNORECASE
    ),
    'salary': re.compile(
        r'\b(salary|ctc|annual\s+income|monthly\s+pay|compensation|wages?|stipend|'
        r'credit\s+score|loan\s+amount|tax\s+return|financial\s+record)\b',
        re.IGNORECASE
    ),
    'insurance': re.compile(
        r'\b(policy\s+no\.?|insurance\s+id|health\s+policy|claim\s+id|'
        r'policy\s+number|subscriber\s+id|insurance\s+number)\b',
        re.IGNORECASE
    ),
}

# Helper regex for value capture after a keyword
_NAME_TOKEN = re.compile(r'\b[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,3}\b')
_GENERIC_VALUE = re.compile(r'\b[A-Za-z0-9][A-Za-z0-9\-_/]{3,30}\b')
_NUMERIC_VALUE = re.compile(r'\b\d{3,20}\b')
_DATE_PATTERN = re.compile(
    r'\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}-\d{2}-\d{2}|'
    r'\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4})\b',
    re.IGNORECASE
)
_UPI_PATTERN = re.compile(r'\b[A-Za-z0-9._\-]{2,}@[A-Za-z]{2,}\b')

_CTX_WINDOW = 80   # characters on each side for proximity checks


class PIIDetector:
    """
    Detects PII in text using a two-layer approach aligned to GDPR and India DPDP Act 2023.

    Layer 1: High-confidence regex patterns (standalone identifiers)
    Layer 2: Contextual-linkage (keyword proximity unlocks weaker patterns)
    """

    def __init__(self):
        self.patterns = self._load_patterns()

    # ------------------------------------------------------------------
    # Layer 1 pattern library
    # ------------------------------------------------------------------
    def _load_patterns(self) -> Dict[str, Dict[str, Any]]:
        return {

            # ── Email ────────────────────────────────────────────────────
            'email': {
                'pattern': re.compile(
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
                ),
                'name': 'Email Address',
                'category': 'email_address',
                'risk': 'MEDIUM',
                'confidence': 0.95,
                'reason': 'Email address directly identifies a person or their personal mailbox.'
            },

            # ── Phone numbers ────────────────────────────────────────────
            'phone': {
                'pattern': re.compile(
                    r'(?<!\d)(\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)'
                ),
                'name': 'Phone Number (US/Generic)',
                'category': 'phone_number',
                'risk': 'MEDIUM',
                'confidence': 0.82,
                'reason': 'Phone number is a direct personal contact identifier.'
            },
            'phone_intl': {
                'pattern': re.compile(
                    r'\+(?!91\b)\d{1,3}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,9}'
                ),
                'name': 'International Phone',
                'category': 'phone_number',
                'risk': 'MEDIUM',
                'confidence': 0.82,
                'reason': 'International phone number is a direct personal contact identifier.'
            },
            'phone_india': {
                'pattern': re.compile(r'\b(?:\+91[\s\-]?)?[6-9]\d{9}\b'),
                'name': 'India Mobile Number',
                'category': 'phone_number',
                'risk': 'MEDIUM',
                'confidence': 0.88,
                'reason': 'India mobile number (10-digit, 6-9 prefix) is a direct personal identifier.'
            },

            # ── Government IDs ───────────────────────────────────────────
            'ssn': {
                'pattern': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
                'name': 'Social Security Number',
                'category': 'national_id',
                'risk': 'CRITICAL',
                'confidence': 0.98,
                'reason': 'US SSN is a government-issued national identifier; CRITICAL risk.'
            },
            'aadhaar': {
                'pattern': re.compile(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'),
                'name': 'Aadhaar Number',
                'category': 'aadhaar_number',
                'risk': 'CRITICAL',
                'confidence': 0.78,
                'reason': 'Aadhaar is a 12-digit India national biometric ID (UIDAI); CRITICAL risk.'
            },
            'pan': {
                'pattern': re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
                'name': 'PAN Number',
                'category': 'pan_number',
                'risk': 'HIGH',
                'confidence': 0.90,
                'reason': 'Permanent Account Number (PAN) is an India government tax/identity document.'
            },
            'passport': {
                'pattern': re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'),
                'name': 'Passport Number',
                'category': 'passport_number',
                'risk': 'HIGH',
                'confidence': 0.72,
                'reason': 'Passport number is a government-issued travel identity document.'
            },

            # ── Payment / financial ──────────────────────────────────────
            'credit_card': {
                'pattern': re.compile(
                    r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))'
                    r'[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4}\b'
                ),
                'name': 'Payment Card Number',
                'category': 'payment_card_number',
                'risk': 'CRITICAL',
                'confidence': 0.88,
                'reason': 'Payment card number enables financial fraud; CRITICAL risk.'
            },
            'iban': {
                'pattern': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'),
                'name': 'IBAN',
                'category': 'banking_identifier',
                'risk': 'HIGH',
                'confidence': 0.82,
                'reason': 'IBAN is an international bank account number linked to a person or account.'
            },

            # ── Network / device identifiers ─────────────────────────────
            'ip_address': {
                'pattern': re.compile(
                    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
                ),
                'name': 'IPv4 Address',
                'category': 'ip_address',
                'risk': 'LOW',
                'confidence': 0.90,
                'reason': 'IPv4 address is an online identifier under GDPR Recital 30.'
            },
            'ipv6': {
                'pattern': re.compile(
                    r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b'
                    r'|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b'
                    r'|\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b'
                    r'|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:\d{1,3}(?:\.\d{1,3}){3}\b'
                ),
                'name': 'IPv6 Address',
                'category': 'ip_address',
                'risk': 'LOW',
                'confidence': 0.92,
                'reason': 'IPv6 address is an online identifier under GDPR Recital 30.'
            },
            'mac_address': {
                'pattern': re.compile(
                    r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'
                ),
                'name': 'MAC Address',
                'category': 'mac_address',
                'risk': 'LOW',
                'confidence': 0.92,
                'reason': 'MAC address uniquely identifies a network device, potentially linked to a person.'
            },
            'imei': {
                'pattern': re.compile(r'\b\d{15}\b'),
                'name': 'IMEI / 15-digit Serial',
                'category': 'device_identifier',
                'risk': 'MEDIUM',
                'confidence': 0.68,
                'reason': 'IMEI is a 15-digit device identifier that can be linked to a device owner.'
            },
            'gps_coords': {
                'pattern': re.compile(
                    r'[-+]?(?:[1-8]?\d(?:\.\d{4,})?|90(?:\.0+)?)'
                    r'\s*[,]\s*'
                    r'[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d{4,})?)'
                ),
                'name': 'GPS Coordinates',
                'category': 'location_precise',
                'risk': 'MEDIUM',
                'confidence': 0.82,
                'reason': 'GPS coordinates reveal precise physical location, which may identify a person.'
            },

            # ── Healthcare ───────────────────────────────────────────────
            'mrn': {
                'pattern': re.compile(
                    r'\b(?:MRN|Medical\s+Record)\s*[:#]?\s*[A-Z]?\d{5,10}\b',
                    re.IGNORECASE
                ),
                'name': 'Medical Record Number',
                'category': 'medical_record_number',
                'risk': 'CRITICAL',
                'confidence': 0.88,
                'reason': 'Medical Record Number is protected health information; CRITICAL risk.'
            },

            # ── Street address (Layer 1 fallback for labelled addresses) ─
            'address': {
                'pattern': re.compile(
                    r'\b\d{1,5}\s+[\w\s]{1,30}\s+'
                    r'(street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|'
                    r'drive|dr|court|ct|sector|block|nagar|marg|vihar)\b',
                    re.IGNORECASE
                ),
                'name': 'Street Address',
                'category': 'postal_address',
                'risk': 'MEDIUM',
                'confidence': 0.70,
                'reason': 'Street address is a precise location identifier that can identify a person.'
            },
        }

    # ------------------------------------------------------------------
    # Layer 2 — contextual-linkage detection
    # ------------------------------------------------------------------
    def _run_layer2(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan for keyword labels and capture nearby values as contextual PII findings.
        Each match carries source='context'.
        """
        findings = []

        def add(category, name, match_text, start, end, confidence, risk, reason):
            findings.append({
                'type': category,
                'name': name,
                'category': category,
                'value': match_text,
                'match_text': match_text,
                'masked': self._mask_value(match_text, category, 'smart'),
                'position': start,
                'start_index': start,
                'end_index': end,
                'confidence': confidence,
                'risk': risk,
                'reason': reason,
                'source': 'context',
            })

        # Personal name
        for kw in _CTX['name'].finditer(text):
            after = text[kw.end(): kw.end() + 80]
            nm = _NAME_TOKEN.search(after)
            if nm:
                s = kw.end() + nm.start()
                e = kw.end() + nm.end()
                add('personal_name_with_context', 'Personal Name',
                    nm.group(0), s, e, 0.80, 'MEDIUM',
                    f'Name-like token after identity label "{kw.group(0)}".')

        # Date of birth (keyword required)
        for kw in _CTX['dob'].finditer(text):
            window = text[max(0, kw.start() - 10): kw.end() + 60]
            dt = _DATE_PATTERN.search(window)
            if dt:
                base = max(0, kw.start() - 10)
                add('date_of_birth', 'Date of Birth',
                    dt.group(0), base + dt.start(), base + dt.end(), 0.92, 'MEDIUM',
                    f'Date token following DOB keyword "{kw.group(0)}".')

        # Address (India-aware label capture)
        for kw in _CTX['address'].finditer(text):
            after = text[kw.end(): kw.end() + 120]
            fragment = re.split(r'[\n|;]', after)[0].strip()[:100]
            if len(fragment) >= 5:
                s = kw.end()
                add('postal_address', 'Postal Address',
                    fragment, s, s + len(fragment), 0.75, 'MEDIUM',
                    f'Address fragment following label "{kw.group(0)}".')

        # Employee ID
        for kw in _CTX['employee_id'].finditer(text):
            after = text[kw.end(): kw.end() + 40]
            val = _NUMERIC_VALUE.search(after) or _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('employee_id', 'Employee ID',
                    val.group(0), s, kw.end() + val.end(), 0.85, 'MEDIUM',
                    f'Employee/staff identifier after label "{kw.group(0)}".')

        # Student ID / Roll no
        for kw in _CTX['student_id'].finditer(text):
            after = text[kw.end(): kw.end() + 40]
            val = _NUMERIC_VALUE.search(after) or _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('student_id', 'Student ID / Roll No',
                    val.group(0), s, kw.end() + val.end(), 0.85, 'MEDIUM',
                    f'Student/roll identifier after label "{kw.group(0)}".')

        # Customer / user ID
        for kw in _CTX['customer_id'].finditer(text):
            after = text[kw.end(): kw.end() + 40]
            val = _NUMERIC_VALUE.search(after) or _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('customer_id', 'Customer / User ID',
                    val.group(0), s, kw.end() + val.end(), 0.80, 'MEDIUM',
                    f'Customer/user identifier after label "{kw.group(0)}".')

        # Username / handle
        for kw in _CTX['username'].finditer(text):
            after = text[kw.end(): kw.end() + 50]
            val = _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('username_or_handle', 'Username / Handle',
                    val.group(0), s, kw.end() + val.end(), 0.80, 'LOW',
                    f'Username/handle after label "{kw.group(0)}".')

        # Health / medical context — flag only when a name is in the same window
        for kw in _CTX['health'].finditer(text):
            ctx_start = max(0, kw.start() - _CTX_WINDOW)
            ctx_end = min(len(text), kw.end() + _CTX_WINDOW)
            window = text[ctx_start:ctx_end]
            if _NAME_TOKEN.search(window):
                add('special_category_or_sensitive_context',
                    'Health Data with Identity',
                    kw.group(0), kw.start(), kw.end(), 0.78, 'HIGH',
                    f'Health keyword "{kw.group(0)}" found near a personal name — special-category PII.')

        # Family / relational identifiers
        for kw in _CTX['family'].finditer(text):
            after = text[kw.end(): kw.end() + 80]
            nm = _NAME_TOKEN.search(after)
            if nm:
                s = kw.end() + nm.start()
                add('family_relationship_with_identity',
                    'Family / Relational Identifier',
                    nm.group(0), s, kw.end() + nm.end(), 0.82, 'MEDIUM',
                    f'Name following family-relationship label "{kw.group(0)}".')

        # Bank account number (context-guarded)
        for kw in _CTX['account'].finditer(text):
            after = text[kw.end(): kw.end() + 50]
            val = _NUMERIC_VALUE.search(after)
            if val and 6 <= len(val.group(0)) <= 18:
                s = kw.end() + val.start()
                add('account_number', 'Bank Account Number',
                    val.group(0), s, kw.end() + val.end(), 0.82, 'CRITICAL',
                    f'Numeric value after bank/account label "{kw.group(0)}".')

        # Vehicle / license plate
        for kw in _CTX['vehicle'].finditer(text):
            after = text[kw.end(): kw.end() + 30]
            val = _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('vehicle_identifier', 'Vehicle / License Plate',
                    val.group(0), s, kw.end() + val.end(), 0.80, 'LOW',
                    f'Vehicle identifier after label "{kw.group(0)}".')

        # Driving licence
        for kw in _CTX['driving_licence'].finditer(text):
            after = text[kw.end(): kw.end() + 30]
            val = _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('driving_licence_number', 'Driving Licence Number',
                    val.group(0), s, kw.end() + val.end(), 0.85, 'HIGH',
                    f'Licence identifier after label "{kw.group(0)}".')

        # Voter ID
        for kw in _CTX['voter'].finditer(text):
            after = text[kw.end(): kw.end() + 30]
            val = _GENERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('voter_id', 'Voter ID',
                    val.group(0), s, kw.end() + val.end(), 0.85, 'HIGH',
                    f'Voter ID value after label "{kw.group(0)}".')

        # UPI ID (context-guarded to prevent overlap with plain email)
        for kw in _CTX['upi'].finditer(text):
            after = text[kw.end(): kw.end() + 60]
            val = _UPI_PATTERN.search(after)
            if val:
                s = kw.end() + val.start()
                add('upi_id', 'UPI ID',
                    val.group(0), s, kw.end() + val.end(), 0.88, 'HIGH',
                    f'UPI payment handle after keyword "{kw.group(0)}".')

        # Cookie / session / advertising ID
        for kw in _CTX['cookie'].finditer(text):
            after = text[kw.end(): kw.end() + 60]
            val = _GENERIC_VALUE.search(after)
            if val and len(val.group(0)) >= 6:
                s = kw.end() + val.start()
                add('cookie_identifier', 'Cookie / Session / Advertising ID',
                    val.group(0), s, kw.end() + val.end(), 0.75, 'LOW',
                    f'Identifier after online-tracker label "{kw.group(0)}".')

        # Insurance ID (context-guarded)
        for kw in _CTX['insurance'].finditer(text):
            after = text[kw.end(): kw.end() + 40]
            val = _GENERIC_VALUE.search(after) or _NUMERIC_VALUE.search(after)
            if val:
                s = kw.end() + val.start()
                add('health_policy_number', 'Insurance / Health Policy ID',
                    val.group(0), s, kw.end() + val.end(), 0.82, 'HIGH',
                    f'Insurance/policy identifier after label "{kw.group(0)}".')

        # Age with identity context (age alone is not PII — requires a name nearby)
        for kw in _CTX['age'].finditer(text):
            ctx_start = max(0, kw.start() - 60)
            window = text[ctx_start: kw.end() + 30]
            name_near = _NAME_TOKEN.search(window)
            age_val = re.search(r'\b\d{1,3}\b', text[kw.end(): kw.end() + 20])
            if age_val and name_near:
                s = kw.end() + age_val.start()
                add('age_with_identity_context', 'Age with Identity Context',
                    age_val.group(0), s, kw.end() + age_val.end(), 0.70, 'LOW',
                    f'Age value near personal name — indirect re-identification risk.')

        # Financial profile (salary/income near a name)
        for kw in _CTX['salary'].finditer(text):
            ctx_start = max(0, kw.start() - _CTX_WINDOW)
            window = text[ctx_start: kw.end() + _CTX_WINDOW]
            if _NAME_TOKEN.search(window):
                add('financial_profile', 'Financial Profile Data',
                    kw.group(0), kw.start(), kw.end(), 0.75, 'HIGH',
                    f'Financial keyword "{kw.group(0)}" near personal name — financial PII.')

        return findings

    # ------------------------------------------------------------------
    # Linked identifier set escalation
    # ------------------------------------------------------------------
    def _build_linked_set(
        self, findings: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Emit a linked_identifier_set finding when 2+ distinct PII categories
        appear within 200 characters of each other in the same text.
        """
        if len(findings) < 2:
            return None

        categories = list({f['category'] for f in findings
                           if f['category'] != 'linked_identifier_set'})
        if len(categories) < 2:
            return None

        sorted_f = sorted(findings, key=lambda x: x['start_index'])
        linked = any(
            sorted_f[i + 1]['start_index'] - sorted_f[i]['end_index'] <= 200
            for i in range(len(sorted_f) - 1)
        )
        if not linked:
            return None

        cat_summary = ', '.join(categories[:5])
        extra = '...' if len(categories) > 5 else ''
        label = f'[{len(categories)} linked PII types: {cat_summary}{extra}]'
        return {
            'type': 'linked_identifier_set',
            'name': 'Linked Identifier Set',
            'category': 'linked_identifier_set',
            'value': label,
            'match_text': label,
            'masked': f'[LINKED SET: {len(categories)} categories]',
            'position': sorted_f[0]['start_index'],
            'start_index': sorted_f[0]['start_index'],
            'end_index': sorted_f[-1]['end_index'],
            'confidence': 0.90,
            'risk': 'CRITICAL',
            'reason': (
                f'Multiple PII categories ({cat_summary}) found in proximity — '
                'combination significantly increases re-identification risk.'
            ),
            'source': 'context',
        }

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------
    @staticmethod
    def _dedup(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings within the same category.
        Findings from different categories are never removed even if spans overlap
        (e.g. a phone number inside an address fragment is still a separate finding).
        """
        if len(findings) <= 1:
            return findings

        # Group by category, then deduplicate within each group
        from collections import defaultdict
        by_cat: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            by_cat[f['category']].append(f)

        kept: List[Dict[str, Any]] = []
        for cat, group in by_cat.items():
            # Sort by confidence desc, then span length desc
            group.sort(key=lambda x: (
                -x['confidence'],
                -(x['end_index'] - x['start_index'])
            ))
            cat_kept: List[Dict[str, Any]] = []
            for f in group:
                # Suppress if span overlaps substantially with an already-kept
                # finding of the same category
                overlap = any(
                    max(f['start_index'], k['start_index']) < min(f['end_index'], k['end_index'])
                    for k in cat_kept
                )
                if not overlap:
                    cat_kept.append(f)
            kept.extend(cat_kept)

        return kept

    # ------------------------------------------------------------------
    # Layer 3 — Driver's licence detection (all 50 US states, context-gated)
    # ------------------------------------------------------------------
    _DL_CONTEXT = re.compile(
        r"(?:driver'?s?\s+licen[sc]e|driving\s+licen[sc]e|DLN?|"
        r"licen[sc]e\s+(?:number|no\.?|#|id)|"
        r"state\s+id|photo\s+id|government\s+id)",
        re.IGNORECASE
    )
    _DL_WINDOW = 150

    @staticmethod
    def _load_dl_patterns() -> List[Dict[str, Any]]:
        return [
            {"states": ["Alabama"],        "pattern": re.compile(r'\b(\d{7,8})\b'),                         "format": "7-8 digits"},
            {"states": ["Alaska"],         "pattern": re.compile(r'\b(\d{7})\b'),                           "format": "7 digits"},
            {"states": ["Arizona"],        "pattern": re.compile(r'\b([A-Z]\d{8,9}|\d{9})\b'),             "format": "1 letter + 8-9 digits OR 9 digits"},
            {"states": ["Arkansas"],       "pattern": re.compile(r'\b(\d{4,9})\b'),                         "format": "4-9 digits"},
            {"states": ["California"],     "pattern": re.compile(r'\b([A-Z]\d{7})\b'),                      "format": "1 letter + 7 digits"},
            {"states": ["Colorado"],       "pattern": re.compile(r'\b(\d{9}|[A-Z]\d{3}[A-Z]\d{3}|[A-Z]\d{8})\b'), "format": "9 digits OR alpha-numeric"},
            {"states": ["Connecticut"],    "pattern": re.compile(r'\b(\d{9})\b'),                           "format": "9 digits"},
            {"states": ["Delaware"],       "pattern": re.compile(r'\b(\d{1,7})\b'),                         "format": "1-7 digits"},
            {"states": ["Florida"],        "pattern": re.compile(r'\b([A-Z]\d{12})\b'),                     "format": "1 letter + 12 digits"},
            {"states": ["Georgia"],        "pattern": re.compile(r'\b(\d{7,9})\b'),                         "format": "7-9 digits"},
            {"states": ["Hawaii"],         "pattern": re.compile(r'\b(H\d{8}|\d{9})\b'),                   "format": "H + 8 digits OR 9 digits"},
            {"states": ["Idaho"],          "pattern": re.compile(r'\b([A-Z]{2}\d{6}[A-Z]|\d{9})\b'),       "format": "2 letters + 6 digits + 1 letter OR 9 digits"},
            {"states": ["Illinois"],       "pattern": re.compile(r'\b([A-Z]\d{11,12})\b'),                  "format": "1 letter + 11-12 digits"},
            {"states": ["Indiana"],        "pattern": re.compile(r'\b(\d{10}|[A-Z]\d{9})\b'),              "format": "10 digits OR 1 letter + 9 digits"},
            {"states": ["Iowa"],           "pattern": re.compile(r'\b(\d{9}|\d{3}[A-Z]{2}\d{4})\b'),       "format": "9 digits OR mixed"},
            {"states": ["Kansas"],         "pattern": re.compile(r'\b([A-Z]\d{8,9}|\d{9})\b'),             "format": "1 letter + 8-9 digits OR 9 digits"},
            {"states": ["Kentucky"],       "pattern": re.compile(r'\b([A-Z]\d{8,9}|\d{9})\b'),             "format": "1 letter + 8-9 digits OR 9 digits"},
            {"states": ["Louisiana"],      "pattern": re.compile(r'\b(\d{9})\b'),                           "format": "9 digits"},
            {"states": ["Maine"],          "pattern": re.compile(r'\b(\d{7,8}|[A-Z]\d{8})\b'),             "format": "7-8 digits OR letter + digits"},
            {"states": ["Maryland"],       "pattern": re.compile(r'\b([A-Z]\d{12})\b'),                     "format": "1 letter + 12 digits"},
            {"states": ["Massachusetts"],  "pattern": re.compile(r'\b(S\d{8}|\d{9})\b'),                   "format": "S + 8 digits OR 9 digits"},
            {"states": ["Michigan"],       "pattern": re.compile(r'\b([A-Z]\d{10})\b'),                     "format": "1 letter + 10 digits"},
            {"states": ["Minnesota"],      "pattern": re.compile(r'\b([A-Z]\d{12})\b'),                     "format": "1 letter + 12 digits"},
            {"states": ["Mississippi"],    "pattern": re.compile(r'\b(\d{9})\b'),                           "format": "9 digits"},
            {"states": ["Missouri"],       "pattern": re.compile(r'\b([A-Z]\d{5,9}|\d{9}|[A-Z]\d{6}R)\b'), "format": "1 letter + 5-9 digits OR 9 digits"},
            {"states": ["Montana"],        "pattern": re.compile(r'\b(\d{13}|[A-Z]{3}\d{10}|[A-Z0-9]{9})\b'), "format": "13 digits OR letter-digit mix"},
            {"states": ["Nebraska"],       "pattern": re.compile(r'\b([A-Z]\d{6,8})\b'),                   "format": "1 letter + 6-8 digits"},
            {"states": ["Nevada"],         "pattern": re.compile(r'\b(\d{9,10}|X\d{8})\b'),                "format": "9-10 digits"},
            {"states": ["New Hampshire"],  "pattern": re.compile(r'\b(\d{2}[A-Z]{3}\d{5})\b'),             "format": "2 digits + 3 letters + 5 digits"},
            {"states": ["New Jersey"],     "pattern": re.compile(r'\b([A-Z]\d{14})\b'),                     "format": "1 letter + 14 digits"},
            {"states": ["New Mexico"],     "pattern": re.compile(r'\b(\d{8,9})\b'),                         "format": "8-9 digits"},
            {"states": ["New York"],       "pattern": re.compile(r'\b(\d{9}|[A-Z]\d{18}|[A-Z]{8}\d)\b'),   "format": "9 digits OR 1 letter + 18 digits"},
            {"states": ["North Carolina"], "pattern": re.compile(r'\b(\d{1,12})\b'),                        "format": "1-12 digits"},
            {"states": ["North Dakota"],   "pattern": re.compile(r'\b([A-Z]{3}\d{6}|\d{9})\b'),            "format": "3 letters + 6 digits OR 9 digits"},
            {"states": ["Ohio"],           "pattern": re.compile(r'\b([A-Z]{2}\d{6}|\d{8})\b'),            "format": "2 letters + 6 digits OR 8 digits"},
            {"states": ["Oklahoma"],       "pattern": re.compile(r'\b([A-Z]\d{9}|\d{9})\b'),               "format": "1 letter + 9 digits OR 9 digits"},
            {"states": ["Oregon"],         "pattern": re.compile(r'\b(\d{1,9}|[A-Z]\d{6})\b'),             "format": "1-9 digits"},
            {"states": ["Pennsylvania"],   "pattern": re.compile(r'\b(\d{8})\b'),                           "format": "8 digits"},
            {"states": ["Rhode Island"],   "pattern": re.compile(r'\b(\d{7}|V\d{6})\b'),                   "format": "7 digits OR V + 6 digits"},
            {"states": ["South Carolina"], "pattern": re.compile(r'\b(\d{5,11})\b'),                        "format": "5-11 digits"},
            {"states": ["South Dakota"],   "pattern": re.compile(r'\b(\d{6,10}|[A-Z]{2}\d{6,8})\b'),       "format": "6-10 digits"},
            {"states": ["Tennessee"],      "pattern": re.compile(r'\b(\d{7,9})\b'),                         "format": "7-9 digits"},
            {"states": ["Texas"],          "pattern": re.compile(r'\b(\d{8})\b'),                           "format": "8 digits"},
            {"states": ["Utah"],           "pattern": re.compile(r'\b(\d{4,10})\b'),                        "format": "4-10 digits"},
            {"states": ["Vermont"],        "pattern": re.compile(r'\b(\d{8}[A-Z])\b'),                      "format": "8 digits + 1 letter"},
            {"states": ["Virginia"],       "pattern": re.compile(r'\b([A-Z]\d{8,11}|\d{9})\b'),            "format": "1 letter + 8-11 digits"},
            {"states": ["Washington"],     "pattern": re.compile(r'\b([A-Z]{3}[A-Z*]{2}\d{3}[A-Z0-9]{2})\b'), "format": "WDL format"},
            {"states": ["West Virginia"],  "pattern": re.compile(r'\b([A-Z0-9]\d{6})\b'),                  "format": "alnum + 6 digits"},
            {"states": ["Wisconsin"],      "pattern": re.compile(r'\b([A-Z]\d{13})\b'),                     "format": "1 letter + 13 digits"},
            {"states": ["Wyoming"],        "pattern": re.compile(r'\b(\d{9,10})\b'),                        "format": "9-10 digits"},
        ]

    def _detect_driver_licenses(self, text: str) -> List[Dict[str, Any]]:
        """Detect US driver's licences only when a DL context keyword is nearby."""
        findings: List[Dict[str, Any]] = []
        seen_positions: List[int] = []

        context_matches = list(self._DL_CONTEXT.finditer(text))
        if not context_matches:
            return findings

        dl_patterns = self._load_dl_patterns()

        for ctx_match in context_matches:
            window_start = max(0, ctx_match.start() - self._DL_WINDOW)
            window_end = min(len(text), ctx_match.start() + self._DL_WINDOW)
            window = text[window_start:window_end]

            for spec in dl_patterns:
                for m in spec["pattern"].finditer(window):
                    abs_pos = window_start + m.start()
                    if any(abs(abs_pos - p) < 8 for p in seen_positions):
                        continue
                    seen_positions.append(abs_pos)
                    value = m.group(1) if m.lastindex else m.group(0)
                    masked = self._mask_value(value, 'driver_license', 'smart')
                    findings.append({
                        'type': 'driver_license',
                        'name': f"Driver's Licence — {', '.join(spec['states'])} format",
                        'category': 'driving_licence_number',
                        'value': value,
                        'match_text': value,
                        'masked': masked,
                        'position': abs_pos,
                        'start_index': abs_pos,
                        'end_index': abs_pos + len(value),
                        'confidence': 0.82,
                        'risk': 'HIGH',
                        'reason': (
                            f"Driver's licence number ({spec['format']}) near DL context keyword "
                            f'"{ctx_match.group(0)}".'
                        ),
                        'source': 'context',
                    })

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def detect_pii(
        self,
        text: str,
        mask: bool = True,
        masking_strategy: str = 'smart',
        include_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Detect PII in text using Layer 1 (regex) + Layer 2 (contextual).

        Args:
            text:             Input text to analyze.
            mask:             Replace PII values in returned masked_text.
            masking_strategy: 'smart' | 'full' | 'partial'
            include_types:    Limit to specific pattern keys (Layer 1 only).

        Returns:
            Dict with keys:
              detected / findings  — list of PII findings (backward + spec)
              masked_text          — text with PII replaced
              pii_counts           — counts by display name
              has_pii / contains_pii — bool (backward + spec)
              count                — total findings
              risk_level           — SAFE | LOW | MEDIUM | HIGH | CRITICAL
              summary              — human-readable explanation
        """
        if not text or not text.strip():
            return {
                'detected': [],
                'findings': [],
                'masked_text': '',
                'pii_counts': {},
                'has_pii': False,
                'contains_pii': False,
                'count': 0,
                'risk_level': 'SAFE',
                'summary': 'No text provided.',
            }

        is_placeholder = bool(_PLACEHOLDER_RE.search(text))
        findings: List[Dict[str, Any]] = []
        pii_counts: Dict[str, int] = {}
        masked_text = text

        patterns_to_check = self.patterns if not include_types else {
            k: v for k, v in self.patterns.items() if k in include_types
        }

        # ── Layer 1: regex patterns ────────────────────────────────────
        for pii_type, cfg in patterns_to_check.items():
            for m in cfg['pattern'].finditer(text):
                value = m.group(0)
                confidence = cfg['confidence']
                if is_placeholder:
                    confidence = max(0.30, confidence - 0.40)

                masked_value = self._mask_value(value, pii_type, masking_strategy) if mask else value
                finding = {
                    'type': pii_type,
                    'name': cfg['name'],
                    'category': cfg['category'],
                    'value': value,
                    'match_text': value,
                    'masked': masked_value,
                    'position': m.start(),
                    'start_index': m.start(),
                    'end_index': m.end(),
                    'confidence': confidence,
                    'risk': cfg['risk'],
                    'reason': cfg['reason'],
                    'source': 'pattern',
                }
                findings.append(finding)
                pii_counts[cfg['name']] = pii_counts.get(cfg['name'], 0) + 1

                if mask:
                    masked_text = masked_text.replace(value, masked_value, 1)

        # ── Layer 2: contextual-linkage ────────────────────────────────
        if not include_types:
            ctx_findings = self._run_layer2(text)
            if is_placeholder:
                for f in ctx_findings:
                    f['confidence'] = max(0.30, f['confidence'] - 0.40)
            findings.extend(ctx_findings)
            for f in ctx_findings:
                pii_counts[f['name']] = pii_counts.get(f['name'], 0) + 1

        # ── Layer 3: driver's licence (all 50 US states, context-gated) ──
        if not include_types:
            dl_findings = self._detect_driver_licenses(text)
            if is_placeholder:
                for f in dl_findings:
                    f['confidence'] = max(0.30, f['confidence'] - 0.40)
            findings.extend(dl_findings)
            for f in dl_findings:
                pii_counts[f['name']] = pii_counts.get(f['name'], 0) + 1

        # ── Dedup overlapping spans ────────────────────────────────────
        findings = self._dedup(findings)

        # ── Sort by position ───────────────────────────────────────────
        findings.sort(key=lambda x: x['start_index'])

        # ── Linked identifier set ──────────────────────────────────────
        if len(findings) >= 2:
            linked = self._build_linked_set(findings)
            if linked:
                findings.append(linked)

        risk_level = self._calculate_risk_level(findings)
        summary = self._build_summary(findings, risk_level, is_placeholder)

        return {
            'detected': findings,         # backward-compat
            'findings': findings,         # spec field
            'masked_text': masked_text,
            'pii_counts': pii_counts,
            'has_pii': len(findings) > 0,
            'contains_pii': len(findings) > 0,
            'count': len(findings),
            'risk_level': risk_level,
            'summary': summary,
        }

    # ------------------------------------------------------------------
    # Masking
    # ------------------------------------------------------------------
    def _mask_value(self, value: str, pii_type: str, strategy: str) -> str:
        if strategy == 'full':
            return '***'
        if strategy == 'partial' and len(value) > 4:
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

        # Smart masking per type
        if pii_type == 'email':
            if '@' in value:
                user, domain = value.split('@', 1)
                return f"{user[0] if user else ''}***@{domain}"
            return '***@***'

        if pii_type in ('phone', 'phone_intl', 'phone_india'):
            digits = re.sub(r'\D', '', value)
            return f"***-***-{digits[-4:]}" if len(digits) >= 4 else '***-***-****'

        if pii_type == 'credit_card':
            digits = re.sub(r'\D', '', value)
            return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else '****-****-****-****'

        if pii_type == 'ssn':
            return f"***-**-{value[-4:]}" if len(value) >= 4 else '***-**-****'

        if pii_type in ('ip_address', 'ipv6'):
            if '.' in value:
                parts = value.split('.')
                return f"{parts[0]}.*.*.*" if len(parts) == 4 else '*.*.*.*'
            return '[IPv6-REDACTED]'

        if pii_type == 'aadhaar':
            digits = re.sub(r'\D', '', value)
            return f"XXXX-XXXX-{digits[-4:]}" if len(digits) >= 4 else 'XXXX-XXXX-XXXX'

        if pii_type == 'pan':
            return f"{value[:2]}***{value[-2:]}" if len(value) >= 5 else '*****'

        if pii_type == 'gps_coords':
            return '[GPS-REDACTED]'

        # Default: keep first 2 and last 2 chars
        if len(value) > 6:
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
        return '*' * len(value)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    def _calculate_risk_level(self, detected: List[Dict[str, Any]]) -> str:
        if not detected:
            return 'SAFE'

        risk_counts: Dict[str, int] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for item in detected:
            risk = item.get('risk', 'MEDIUM')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        if risk_counts['CRITICAL'] > 0:
            return 'CRITICAL'
        if risk_counts['HIGH'] > 1 or len(detected) > 5:
            return 'HIGH'
        if risk_counts['HIGH'] > 0 or risk_counts['MEDIUM'] > 2:
            return 'MEDIUM'
        return 'LOW'

    def _build_summary(
        self,
        findings: List[Dict[str, Any]],
        risk_level: str,
        is_placeholder: bool
    ) -> str:
        if not findings:
            return 'No PII detected.'
        cats = list({
            f['category'] for f in findings
            if f['category'] != 'linked_identifier_set'
        })
        note = ' (placeholder/test context detected — confidence downgraded)' if is_placeholder else ''
        extra = '...' if len(cats) > 5 else ''
        return (
            f"{len(findings)} PII finding(s) detected: {', '.join(cats[:5])}{extra}. "
            f"Risk: {risk_level}.{note}"
        )

    # ------------------------------------------------------------------
    # Utility methods (preserved for backward compatibility)
    # ------------------------------------------------------------------
    def get_pattern_info(self, pii_type: str) -> Optional[Dict[str, Any]]:
        return self.patterns.get(pii_type)

    def list_supported_types(self) -> List[str]:
        return list(self.patterns.keys())

    def list_by_category(self, category: str) -> List[str]:
        return [
            pii_type for pii_type, cfg in self.patterns.items()
            if cfg['category'] == category
        ]


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python pii_detector.py <text> [mask] [strategy]")
        print("  mask:     true/false (default: true)")
        print("  strategy: smart/full/partial (default: smart)")
        sys.exit(1)

    text = sys.argv[1]
    mask = sys.argv[2].lower() != 'false' if len(sys.argv) > 2 else True
    strategy = sys.argv[3] if len(sys.argv) > 3 else 'smart'

    detector = PIIDetector()
    result = detector.detect_pii(text, mask=mask, masking_strategy=strategy)

    # Print without full findings list for readability
    summary_out = {
        'contains_pii': result['contains_pii'],
        'count': result['count'],
        'risk_level': result['risk_level'],
        'summary': result['summary'],
        'findings': [
            {
                'category': f['category'],
                'name': f['name'],
                'match_text': f['match_text'],
                'confidence': f['confidence'],
                'risk': f['risk'],
                'source': f['source'],
                'reason': f['reason'],
            }
            for f in result['findings']
        ]
    }
    print(json.dumps(summary_out, indent=2))
