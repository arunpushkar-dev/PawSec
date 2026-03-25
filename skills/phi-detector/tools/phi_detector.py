#!/usr/bin/env python3
"""
PHI Detector - HIPAA Protected Health Information Detection

Detects PHI (Protected Health Information) as defined by HIPAA's Privacy Rule.
Designed with ZERO OVERLAP against the pii-detector skill.

Design Principle:
  PII Detector covers: SSN, email, phone, passport, DOB, credit card, bank
  account, MRN, insurance_id (BC-XXXXXXX), address, zip, IP, API key, MAC.

  PHI Detector covers EVERYTHING ELSE under HIPAA that constitutes PHI:
  - Medical administrative codes (NPI, DEA, CPT, ICD-10, HCPCS, NDC, UDI)
  - Health plan identifiers not covered by PII (beneficiary numbers, group IDs,
    Rx numbers, lab accession numbers)
  - Health context patterns: diagnoses, medications, lab results, vital signs
  - Extra-sensitive PHI categories: mental health, HIV/AIDS, substance abuse,
    genetic information, reproductive health
  - HIPAA-specific temporal: admission/discharge dates, death dates, age > 89

References:
  - HIPAA Privacy Rule 45 CFR §164.514(b) - Safe Harbor 18 identifiers
  - HIPAA Privacy Rule 45 CFR §164.502 - Definition of PHI
  - 45 CFR §164.514(b)(2) - Expert Determination method
  - HHS Guidance on De-identification (November 2012)
  - HIPAA Omnibus Rule (2013) - Genetic information as PHI
  - 42 CFR Part 2 - Substance Use Disorder extra protections
"""

import re
from typing import Dict, List, Any, Tuple


# ---------------------------------------------------------------------------
# Context window size (chars) around a match to check for patient linkage
# ---------------------------------------------------------------------------
CONTEXT_WINDOW = 250


# ---------------------------------------------------------------------------
# Personal/patient context markers — used to confirm linkage to an individual
# ---------------------------------------------------------------------------
PERSONAL_CONTEXT_PATTERNS = re.compile(
    r'\b(patient|pt\b|client|resident|member|subject|participant|'
    r'individual|person|name|dob|born|age|gender|sex|male|female|'
    r'he|she|they|his|her|their|i have|i am|i was|my|'
    r'admitted|discharged|presenting|diagnosed|treated|prescribed|'
    r'referred|consult(?:ed)?|encounter|visit|case|record|chart|'
    r'mr\b|mrs\b|ms\b|dr\b)\b',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# ICD-10 High-sensitivity condition groups (diseases mapped to people)
# We detect codes + plaintext diagnosis terms.
# ---------------------------------------------------------------------------

# ICD-10 code pattern: letter + 2 digits + optional decimal + up to 4 more chars
ICD10_CODE_RE = re.compile(
    r'\b([A-Z]\d{2}(?:\.\d{1,4})?)\b',
    re.IGNORECASE
)

# Prefix/label that confirms it's being used as a medical code
ICD10_LABEL_RE = re.compile(
    r'\b(ICD[-\s]?10|ICD[-\s]?9|diagnosis code|dx code|'
    r'diagnostic code|primary dx|secondary dx|admitting dx|'
    r'discharge dx|billable code|condition code)\b',
    re.IGNORECASE
)

# ICD-9 codes: 3-5 digits, optional decimal
ICD9_CODE_RE = re.compile(
    r'\b(\d{3}(?:\.\d{1,2})?)\b'
)

# ── High-sensitivity health condition terms (plaintext diagnosis) ────────────
# Each entry: (regex_pattern, category_name, sensitivity_level)
CONDITION_PATTERNS: List[Tuple[re.Pattern, str, str]] = [

    # Mental health (extra sensitive under HIPAA + state laws)
    (re.compile(
        r'\b(major\s+depressive\s+disorder|clinical\s+depression|'
        r'severe\s+depression|acute\s+depression|depressive\s+episode|'
        r'treatment[- ]resistant\s+depression|'
        r'bipolar\s+disorder|bipolar\s+[I]+|bipolar\s+diagnosis|'
        r'manic\s+episode|manic[- ]depressive|'
        r'schizophrenia|schizoaffective|'
        r'acute\s+psychosis|psychotic\s+break|psychosis|psychotic\s+episode|'
        r'post[- ]traumatic\s+stress|PTSD|obsessive[- ]compulsive|OCD|'
        r'panic\s+disorder|generalized\s+anxiety\s+disorder|'
        r'borderline\s+personality|antisocial\s+personality|eating\s+disorder|'
        r'anorexia\s+nervosa|bulimia\s+nervosa|binge\s+eating|ADHD|attention\s+'
        r'deficit|autism\s+spectrum|ASD|intellectual\s+disability|dementia|'
        r'Alzheimer\'?s|suicidal\s+ideation|self[- ]harm|self[- ]injury|'
        r'psychiatric\s+hospitalization|inpatient\s+psych|mental\s+health\s+'
        r'diagnosis|involuntary\s+hold|5150|Baker\s+Act)\b',
        re.IGNORECASE),
     'Mental Health Condition', 'CRITICAL'),

    # Substance use disorder (42 CFR Part 2 — most protected PHI in USA)
    (re.compile(
        r'\b(substance\s+use\s+disorder|SUD\b|opioid\s+use\s+disorder|OUD\b|'
        r'alcohol\s+use\s+disorder|AUD\b|drug\s+dependence|drug\s+addiction|'
        r'opioid\s+dependence|heroin\s+dependence|methamphetamine\s+use|'
        r'cocaine\s+dependence|benzodiazepine\s+dependence|methadone\s+'
        r'treatment|buprenorphine\s+treatment|suboxone\s+treatment|'
        r'naltrexone\s+treatment|MAT\s+program|medication[- ]assisted\s+'
        r'treatment|in\s+recovery\s+from|rehab(?:ilitation)?\s+program|'
        r'detox(?:ification)?\s+program|narcotics\s+anonymous|AA\s+program|'
        r'alcoholism\s+diagnosis|alcohol\s+dependence|'
        r'overdose\s+(?:treatment|recovery|episode|event|history)|'
        r'drug\s+overdose|opioid\s+overdose|naloxone\s+administered)\b',
        re.IGNORECASE),
     'Substance Use Disorder', 'CRITICAL'),

    # HIV/AIDS (heavily regulated disclosure)
    (re.compile(
        r'\b(HIV[- ]positive|HIV\+|human\s+immunodeficiency\s+virus|AIDS\b|'
        r'acquired\s+immunodeficiency\s+syndrome|CD4\s+count|viral\s+load\s+'
        r'undetectable|antiretroviral\s+therapy|ART\s+regimen|PrEP\s+user|'
        r'post[- ]exposure\s+prophylaxis|PEP\s+treatment|HIV\s+diagnosis|'
        r'HIV\s+status|HIV\s+test\s+result|HIV\s+infected)\b',
        re.IGNORECASE),
     'HIV/AIDS Status', 'CRITICAL'),

    # Sexually transmitted infections (high sensitivity)
    (re.compile(
        r'\b(gonorrhea|chlamydia|syphilis|herpes\s+simplex|HSV[-\s]?[12]|'
        r'genital\s+herpes|genital\s+warts|HPV\s+diagnosis|hepatitis\s+[BC]\s+'
        r'diagnosis|Hep\s+[BC]\s+positive|sexually\s+transmitted\s+'
        r'infection|STI\s+diagnosis|STD\s+diagnosis|trichomoniasis|'
        r'bacterial\s+vaginosis\s+diagnosis)\b',
        re.IGNORECASE),
     'Sexually Transmitted Infection', 'CRITICAL'),

    # Genetic information (HIPAA Omnibus 2013 added GINA coverage)
    (re.compile(
        r'\b(BRCA[12]?\s+(?:positive|mutation|variant)|genetic\s+test\s+'
        r'result|genetic\s+mutation\s+found|hereditary\s+cancer\s+syndrome|'
        r'Lynch\s+syndrome|Huntington\'?s\s+disease|genetic\s+disorder\s+'
        r'diagnosis|chromosomal\s+abnormality|Down\s+syndrome\s+diagnosis|'
        r'Trisomy\s+\d+|cystic\s+fibrosis\s+gene|CFTR\s+mutation|'
        r'sickle\s+cell\s+trait|sickle\s+cell\s+disease|'
        r'familial\s+hypercholesterolemia|genetic\s+carrier\s+status|'
        r'pharmacogenomic\s+test|DNA\s+test\s+result|exome\s+sequencing\s+'
        r'result|genome\s+sequencing\s+result)\b',
        re.IGNORECASE),
     'Genetic Information', 'CRITICAL'),

    # Reproductive / pregnancy health
    (re.compile(
        r'\b(pregnant\s+with|current\s+pregnancy|gestational\s+age|'
        r'estimated\s+due\s+date|EDD\b|weeks\s+gestation|gravida|para\s+\d|'
        r'G\d+P\d+|abortion\s+procedure|termination\s+of\s+pregnancy|'
        r'miscarriage|pregnancy\s+loss|spontaneous\s+abortion|'
        r'ectopic\s+pregnancy|IVF\s+treatment|'
        r'in\s+vitro\s+fertilization|fertility\s+treatment|infertility\s+'
        r'diagnosis|IUI\s+procedure|egg\s+retrieval|sperm\s+analysis\s+'
        r'result|tubal\s+ligation|vasectomy\s+record|contraceptive\s+'
        r'implant|reproductive\s+health\s+record)\b',
        re.IGNORECASE),
     'Reproductive Health', 'CRITICAL'),

    # Cancer diagnoses
    (re.compile(
        r'\b(cancer\s+diagnosis|malignant\s+neoplasm|carcinoma\s+of|'
        r'adenocarcinoma|squamous\s+cell\s+carcinoma|basal\s+cell\s+carcinoma|'
        r'lymphoma\s+diagnosis|leukemia\s+diagnosis|melanoma\s+diagnosis|'
        r'stage\s+[I]{1,3}V?\s+cancer|stage\s+[1-4]\s+cancer|metastatic\s+'
        r'cancer|oncology\s+patient|chemotherapy\s+patient|radiation\s+'
        r'therapy\s+for\s+cancer|tumor\s+marker\s+result|PSA\s+elevated|'
        r'CA[- ]?125\s+level|CA[- ]?19[- ]?9\s+level|CEA\s+level|'
        r'biopsy\s+result\s+malignant|pathology\s+report\s+malignant)\b',
        re.IGNORECASE),
     'Cancer Diagnosis', 'CRITICAL'),

    # Chronic serious conditions
    (re.compile(
        r'\b(type\s+[12]\s+diabetes|diabetes\s+mellitus\s+type\s+[12]|'
        r'T[12]DM\b|insulin[- ]dependent\s+diabetes|end[- ]stage\s+renal\s+'
        r'disease|ESRD\b|chronic\s+kidney\s+disease\s+stage\s+[1-5]|CKD\s+'
        r'stage\s+[1-5]|congestive\s+heart\s+failure|CHF\s+diagnosis|'
        r'coronary\s+artery\s+disease|CAD\s+diagnosis|myocardial\s+infarction|'
        r'heart\s+attack\s+history|stroke\s+history|CVA\s+history|'
        r'COPD\s+diagnosis|emphysema\s+diagnosis|cirrhosis\s+diagnosis|'
        r'hepatic\s+failure|liver\s+failure\s+diagnosis|seizure\s+disorder|'
        r'epilepsy\s+diagnosis|multiple\s+sclerosis|MS\s+diagnosis|'
        r'Parkinson\'?s\s+disease|ALS\b|amyotrophic\s+lateral\s+sclerosis|'
        r'rheumatoid\s+arthritis\s+diagnosis|lupus\s+diagnosis|SLE\b|'
        r'IBD\s+diagnosis|Crohn\'?s\s+disease\s+diagnosis|ulcerative\s+'
        r'colitis\s+diagnosis)\b',
        re.IGNORECASE),
     'Serious Chronic Condition', 'HIGH'),
]

# ── Medication + dosage patterns ─────────────────────────────────────────────
# Drug names near dosage info linked to a person constitutes PHI

# Generic drug classes that require prescription context
MEDICATION_CLASS_RE = re.compile(
    r'\b(oxycodone|oxycontin|hydrocodone|vicodin|fentanyl|morphine|codeine|'
    r'buprenorphine|suboxone|methadone|tramadol|dilaudid|hydromorphone|'
    r'percocet|norco|xanax|alprazolam|valium|diazepam|klonopin|clonazepam|'
    r'ativan|lorazepam|ambien|zolpidem|adderall|amphetamine|ritalin|'
    r'methylphenidate|concerta|vyvanse|lisdexamfetamine|dexedrine|'
    r'lithium\s+carbonate|quetiapine|seroquel|olanzapine|zyprexa|'
    r'risperidone|risperdal|aripiprazole|abilify|clozapine|clozaril|'
    r'haloperidol|haldol|paliperidone|invega|ziprasidone|geodon|'
    r'sertraline|zoloft|fluoxetine|prozac|paroxetine|paxil|'
    r'escitalopram|lexapro|citalopram|celexa|venlafaxine|effexor|'
    r'duloxetine|cymbalta|bupropion|wellbutrin|mirtazapine|remeron|'
    r'warfarin|coumadin|heparin|enoxaparin|lovenox|apixaban|eliquis|'
    r'rivaroxaban|xarelto|dabigatran|pradaxa|clopidogrel|plavix|'
    r'atorvastatin|lipitor|simvastatin|zocor|rosuvastatin|crestor|'
    r'metformin|glucophage|insulin\s+(?:glargine|lispro|aspart|detemir|'
    r'degludec|NPH|regular)|humalog|lantus|novolog|levemir|tresiba|'
    r'lisinopril|enalapril|ramipril|metoprolol|lopressor|atenolol|'
    r'amlodipine|norvasc|losartan|cozaar|valsartan|diovan|'
    r'levothyroxine|synthroid|prednisone|prednisolone|dexamethasone|'
    r'azithromycin|amoxicillin|ciprofloxacin|doxycycline|vancomycin|'
    r'tacrolimus|prograf|cyclosporine|mycophenolate|cellcept|'
    r'imatinib|gleevec|erlotinib|tarceva|bevacizumab|avastin|'
    r'trastuzumab|herceptin|rituximab|rituxan|pembrolizumab|keytruda|'
    r'nivolumab|opdivo|exemestane|aromasin|tamoxifen|anastrozole|'
    r'arimidex|leuprolide|lupron|finasteride|dutasteride)\b',
    re.IGNORECASE
)

# Dosage pattern (ensures it's actually a prescription context)
DOSAGE_RE = re.compile(
    r'\b\d+(?:\.\d+)?\s*(?:mg|mcg|mEq|units?|IU|ml|mL|g|mmol)\b(?:/(?:day|'
    r'week|month|dose|kg|hr|min))?',
    re.IGNORECASE
)

# Prescription instruction patterns
PRESCRIPTION_CONTEXT_RE = re.compile(
    r'\b(prescribed\s+\w|taking\s+\w|on\s+a\s+dose\s+of|dosage\s+of|'
    r'dose:\s*\d|sig:\s*\w|dispense\s+#|quantity:\s*\d|refill|'
    r'\d+\s*mg\s+(?:daily|twice|three\s+times|QD|BID|TID|QID)|'
    r'po\s+\w|SL\s+\w|topical\s+\w|injection\s+of\s+\w)\b',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Administrative Medical Identifiers (purely medical, never overlap with PII)
# ---------------------------------------------------------------------------

class PHIPattern:
    """Container for a PHI detection pattern."""
    def __init__(self, name: str, category: str, pattern: re.Pattern,
                 severity: str, requires_context: bool = False,
                 mask_char: str = 'X'):
        self.name = name
        self.category = category
        self.pattern = pattern
        self.severity = severity
        self.requires_context = requires_context
        self.mask_char = mask_char


ADMIN_PHI_PATTERNS: List[PHIPattern] = [

    # ── NPI (National Provider Identifier) ──────────────────────────────────
    # HIPAA identifier #11 (certificate/license). 10-digit, starts 1 or 2.
    PHIPattern(
        name='National Provider Identifier (NPI)',
        category='Medical Provider Identifier',
        pattern=re.compile(
            r'\bNPI[:\s#-]*([12]\d{9})\b|'
            r'\bNational\s+Provider\s+ID[:\s#-]*([12]\d{9})\b|'
            r'\bProvider\s+NPI[:\s#-]*([12]\d{9})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── DEA Number (Drug Enforcement Administration) ────────────────────────
    # Format: 2 letters + 7 digits. Letter 1 = registrant type, letter 2 =
    # first letter of last name, digits include check digit.
    PHIPattern(
        name='DEA Registration Number',
        category='Medical Provider Identifier',
        pattern=re.compile(
            r'\bDEA[:\s#-]*([A-Z]{2}\d{7})\b|'
            r'\bDrug\s+Enforcement\s+(?:Admin|Administration)[:\s#-]*([A-Z]{2}\d{7})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── Health Plan Beneficiary Number ──────────────────────────────────────
    # HIPAA identifier #9. More comprehensive than PII's narrow insurance_id.
    PHIPattern(
        name='Health Plan Beneficiary Number',
        category='Health Insurance Identifier',
        pattern=re.compile(
            r'\b(?:Health\s+Plan\s+)?Beneficiary\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|'
            r'\bMember\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|'
            r'\bSubscriber\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|'
            r'\bEnrollment\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|'
            r'\bPlan\s+Member\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── Health Insurance Group Number ────────────────────────────────────────
    # Separate from member ID; identifies the employer/plan group.
    PHIPattern(
        name='Health Insurance Group Number',
        category='Health Insurance Identifier',
        pattern=re.compile(
            r'\bGroup\s+(?:No|Number|ID|#|Policy(?:\s+No)?)[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|'
            r'\bPolicy\s+Group[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|'
            r'\bEmployer\s+Group\s+(?:No|Number|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── Prescription Number (Rx) ─────────────────────────────────────────────
    # HIPAA identifier: unique pharmacy prescription number.
    PHIPattern(
        name='Prescription Number',
        category='Pharmacy Identifier',
        pattern=re.compile(
            r'\bRx\s*(?:No|Number|#)[:\s#-]*(\d{6,12})\b|'
            r'\bRx[:\s#]*(\d{6,12})\b|'
            r'\bPrescription\s+(?:No|Number|#)[:\s#-]*(\d{6,12})\b|'
            r'\bRx\s+ID[:\s#-]*(\d{6,12})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── Lab / Specimen Accession Number ─────────────────────────────────────
    # Identifies a specific lab specimen; links test results to a patient.
    PHIPattern(
        name='Lab Accession Number',
        category='Laboratory Identifier',
        pattern=re.compile(
            r'\bAccession\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|'
            r'\bACC[:\s#-]*([A-Z]{0,3}[-]?\d{6,12})\b|'
            r'\bSpecimen\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|'
            r'\bLab\s+(?:No|Number|#|ID|Order)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|'
            r'\bOrder\s+(?:No|Number|#)[:\s#-]*([A-Z]{0,2}[-]?\d{6,12})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── Radiology / Pathology Order Number ──────────────────────────────────
    PHIPattern(
        name='Radiology/Pathology Order Number',
        category='Diagnostic Identifier',
        pattern=re.compile(
            r'\bRadiology\s+(?:Order|No|Number|#)[:\s#-]*([A-Z0-9]{6,14})\b|'
            r'\bPathology\s+(?:Report|No|Number|#|ID)[:\s#-]*([A-Z0-9]{6,14})\b|'
            r'\bImaging\s+(?:Order|No|Number)[:\s#-]*([A-Z0-9]{6,14})\b|'
            r'\bPath\s+(?:No|Report\s+No)[:\s#-]*([A-Z0-9]{6,14})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── FDA Unique Device Identifier (UDI) ───────────────────────────────────
    # Identifies implanted/used medical devices linked to a patient.
    # Format: (01)GTIN(11)MFG_DATE(17)EXP_DATE(10)LOT or labeled.
    PHIPattern(
        name='Medical Device Identifier (UDI)',
        category='Medical Device Identifier',
        pattern=re.compile(
            r'\bUDI[:\s#-]*\(?01\)?[\s]*(\d{14})\b|'
            r'\bDevice\s+(?:Serial|UDI|ID|#)[:\s#-]*([A-Z0-9]{8,20})\b|'
            r'\bImplant\s+(?:Serial|ID|#)[:\s#-]*([A-Z0-9]{8,20})\b|'
            r'\bPacemaker\s+(?:Serial|ID|#)[:\s#-]*([A-Z0-9]{6,16})\b|'
            r'\bDefibrillator\s+(?:Serial|ID|#)[:\s#-]*([A-Z0-9]{6,16})\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── CPT (Current Procedural Terminology) Code ────────────────────────────
    # 5-digit codes 10000-99999 identifying medical procedures.
    # Require label context to avoid false positives with random 5-digit numbers.
    PHIPattern(
        name='CPT Procedure Code',
        category='Clinical Code',
        pattern=re.compile(
            r'\bCPT[:\s#-]*(\d{5})\b|'
            r'\bProcedure\s+Code[:\s#-]*(\d{5})\b|'
            r'\bProc\s+Code[:\s#-]*(\d{5})\b|'
            r'\bService\s+Code[:\s#-]*([0-9]{5}[A-Z]?)\b',
            re.IGNORECASE
        ),
        severity='MEDIUM'
    ),

    # ── HCPCS Level II Code ──────────────────────────────────────────────────
    # Letter A-V followed by 4 digits. Identifies supplies, equipment, services.
    PHIPattern(
        name='HCPCS Level II Code',
        category='Clinical Code',
        pattern=re.compile(
            r'\bHCPCS[:\s#-]*([A-V]\d{4})\b|'
            r'\bHCPC\s+Code[:\s#-]*([A-V]\d{4})\b|'
            r'\bSupply\s+Code[:\s#-]*([A-V]\d{4})\b',
            re.IGNORECASE
        ),
        severity='MEDIUM'
    ),

    # ── NDC Drug Code ────────────────────────────────────────────────────────
    # National Drug Code: 10 or 11 digits in 3 segments (5-4-2 or 5-3-2 etc.)
    # Identifies specific drug products linked to prescriptions.
    PHIPattern(
        name='NDC Drug Code',
        category='Pharmacy Identifier',
        pattern=re.compile(
            r'\bNDC[:\s#-]*(\d{4,5}[-]\d{3,4}[-]\d{1,2})\b|'
            r'\bNational\s+Drug\s+Code[:\s#-]*(\d{4,5}[-]\d{3,4}[-]\d{1,2})\b|'
            r'\bNDC[:\s#-]*(\d{10,11})\b',
            re.IGNORECASE
        ),
        severity='MEDIUM'
    ),

    # ── Clinical Trial Identifier ────────────────────────────────────────────
    # ClinicalTrials.gov: NCT + 8 digits. Links patient to trial enrollment.
    PHIPattern(
        name='Clinical Trial ID',
        category='Research Identifier',
        pattern=re.compile(
            r'\b(NCT\d{8})\b|'
            r'\bClinical\s+Trial\s+(?:No|Number|#|ID)[:\s#-]*(NCT\d{8})\b|'
            r'\bTrial\s+Enrollment\s+(?:No|#)[:\s#-]*([A-Z0-9]{6,14})\b',
            re.IGNORECASE
        ),
        severity='MEDIUM'
    ),

    # ── Medical Encounter / Visit Number ────────────────────────────────────
    PHIPattern(
        name='Medical Encounter Number',
        category='Medical Administrative',
        pattern=re.compile(
            r'\bEncounter\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|'
            r'\bVisit\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|'
            r'\bAdmission\s+(?:No|Number|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|'
            r'\bCase\s+(?:No|Number|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b',
            re.IGNORECASE
        ),
        severity='HIGH',
        requires_context=True
    ),

    # ── ICD-10 Code with Label ───────────────────────────────────────────────
    PHIPattern(
        name='ICD-10 Diagnosis Code',
        category='Clinical Code',
        pattern=re.compile(
            r'\bICD[-\s]?10[-\s]?(?:CM|PCS)?[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|'
            r'\bDx\s+Code[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|'
            r'\bDiagnosis\s+Code[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|'
            r'\bPrimary\s+Dx[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|'
            r'\bDischarge\s+Dx[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b',
            re.IGNORECASE
        ),
        severity='HIGH'
    ),

    # ── Vital Signs (clinical measurements in patient context) ──────────────
    # Blood pressure, HR, SpO2, temperature, weight/BMI — need patient context
    PHIPattern(
        name='Clinical Vital Signs',
        category='Clinical Measurement',
        pattern=re.compile(
            r'\b(?:BP|blood\s+pressure)[:\s]*(\d{2,3}/\d{2,3})\s*mm\s*Hg\b|'
            r'\b(?:HR|heart\s+rate|pulse)[:\s]*(\d{2,3})\s*bpm\b|'
            r'\b(?:SpO2|oxygen\s+saturation|O2\s+sat)[:\s]*(\d{2,3})\s*%|'
            r'\b(?:Temp|temperature)[:\s]*(\d{2,3}(?:\.\d)?)\s*[°]?[CF]\b|'
            r'\b(?:RR|respiratory\s+rate)[:\s]*(\d{1,2})\s*(?:breaths?/min|rpm)\b|'
            r'\b(?:BMI)[:\s]*(\d{1,2}(?:\.\d{1,2})?)\s*(?:kg/m2|kg/m\xb2)?\b|'
            r'\bWeight[:\s]*(\d{2,3}(?:\.\d)?)\s*(?:lbs?|kg)\b',
            re.IGNORECASE
        ),
        severity='HIGH',
        requires_context=True
    ),

    # ── Lab Results ──────────────────────────────────────────────────────────
    # Specific numeric lab values that identify health status of a person.
    PHIPattern(
        name='Laboratory Result',
        category='Clinical Measurement',
        pattern=re.compile(
            r'\b(?:HbA1c|A1C|hemoglobin\s+A1C)[:\s]*(\d{1,2}(?:\.\d)?)\s*%|'
            r'\b(?:fasting\s+)?(?:blood\s+glucose|glucose)[:\s]*(\d{2,3})\s*mg/dL\b|'
            r'\b(?:PSA|prostate[- ]specific\s+antigen)[:\s]*(\d+(?:\.\d+)?)\s*ng/mL\b|'
            r'\b(?:TSH|thyroid[- ]stimulating\s+hormone)[:\s]*(\d+(?:\.\d+)?)\s*(?:mIU/L|µIU/mL)\b|'
            r'\b(?:creatinine)[:\s]*(\d+(?:\.\d+)?)\s*mg/dL\b|'
            r'\b(?:eGFR)[:\s]*(\d{1,3})\s*mL/min\b|'
            r'\b(?:INR|PT)[:\s]*(\d+(?:\.\d+)?)\b|'
            r'\b(?:CD4\s+(?:count|cells?))[:\s]*(\d{2,4})\s*(?:cells/μL|cells/mm3|/μL)?\b|'
            r'\b(?:viral\s+load)[:\s]*(\d+)\s*(?:copies/mL|IU/mL)?\b|'
            r'\b(?:total\s+cholesterol|LDL|HDL)[:\s]*(\d{2,3})\s*mg/dL\b|'
            r'\b(?:troponin)[:\s]*(\d+(?:\.\d+)?)\s*(?:ng/mL|μg/L)\b|'
            r'\b(?:platelet\s+count|platelets)[:\s]*(\d{2,3}(?:,\d{3})?)\s*(?:K/μL|×10³/μL)?\b',
            re.IGNORECASE
        ),
        severity='HIGH',
        requires_context=True
    ),

    # ── HIPAA Age > 89 ───────────────────────────────────────────────────────
    # HIPAA requires suppression of ages > 89 (they become "90 or older").
    PHIPattern(
        name='Age Over 89 (HIPAA Suppressed)',
        category='HIPAA Temporal Identifier',
        pattern=re.compile(
            r'\b(?:age[:\s]*|aged\s+|is\s+)(9\d|1[01]\d)\s*(?:years?(?:\s+old)?|yr\.?s?)\b|'
            r'\b(9\d|1[01]\d)[- ]year[- ]old\s+(?:patient|man|woman|male|female|person)\b',
            re.IGNORECASE
        ),
        severity='MEDIUM'
    ),

    # ── Medical Event Dates (admission, discharge, death, procedure) ─────────
    # General DOB is in PII. These are MEDICAL event dates only.
    PHIPattern(
        name='Medical Event Date',
        category='HIPAA Temporal Identifier',
        pattern=re.compile(
            r'\b(?:admission|admitted|admit)\s+date[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|'
            r'\b(?:discharge|discharged)\s+date[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|'
            r'\b(?:date\s+of\s+death|death\s+date|DOD)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|'
            r'\b(?:procedure|surgery|operation|transplant)\s+date[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|'
            r'\b(?:date\s+of\s+service|DOS|service\s+date)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b',
            re.IGNORECASE
        ),
        severity='MEDIUM'
    ),

    # ── Biometric Health Identifiers ─────────────────────────────────────────
    # HIPAA identifier #16. Fingerprints, retinal scans, voiceprints in health.
    PHIPattern(
        name='Biometric Health Identifier',
        category='Biometric Identifier',
        pattern=re.compile(
            r'\b(?:fingerprint\s+(?:scan|match|record|ID|used\s+for|for\s+patient)|'
            r'retinal\s+(?:scan|ID|map)|iris\s+(?:scan|ID)|'
            r'voiceprint\s+(?:record|ID|used|for|to\s+verify|verification)|'
            r'voice\s+(?:verification|authentication)\s+(?:for\s+)?(?:patient|member)|'
            r'facial\s+(?:recognition|scan|photograph)\s+(?:match|ID|on\s+file)?|'
            r'patient\s+(?:face\s+photo|photograph|facial\s+photo|clinical\s+photo)|'
            r'full[-\s]?face\s+(?:photo|photograph|image)|'
            r'clinical\s+photograph|'
            r'DNA\s+(?:profile|sample|match|sequence)\s+(?:on\s+)?file|'
            r'blood\s+type[:\s]*(?:A|B|AB|O)[+-])\b',
            re.IGNORECASE
        ),
        severity='HIGH',
        requires_context=True
    ),

    # ── Clinical Notes Patterns ──────────────────────────────────────────────
    # Clinical note context phrases that frame health information about a person.
    PHIPattern(
        name='Clinical Notes Context',
        category='Clinical Documentation',
        pattern=re.compile(
            r'\b(?:chief\s+complaint[:\s]|CC[:\s](?:\w+)){1}|'
            r'\b(?:history\s+of\s+present\s+illness[:\s]|HPI[:\s])|'
            r'\b(?:assessment\s+and\s+plan[:\s]|A(?:ssessment)?[:\s]?(?:&|and)\s*P(?:lan)?[:\s])|'
            r'\b(?:past\s+medical\s+history[:\s]|PMH[:\s]|PMHx[:\s])|'
            r'\b(?:review\s+of\s+systems[:\s]|ROS[:\s])|'
            r'\b(?:physical\s+exam(?:ination)?[:\s]|PE[:\s](?=[A-Z]))|'
            r'\b(?:patient\s+(?:presents?|presented|is\s+a|reports?)\s+(?:with|to))|'
            r'\b(?:subjective[:\s]|objective[:\s]|SOAP\s+note)|'
            r'\b(?:impression[:\s]\s*\d\.)|'
            r'\b(?:discharge\s+summary|admission\s+note|progress\s+note|'
            r'operative\s+report|consultation\s+note)\b',
            re.IGNORECASE
        ),
        severity='HIGH',
        requires_context=True
    ),

    # ── Physician/Facility Name in Clinical Context ──────────────────────────
    # HIPAA identifier #1 and #2 — names/geo data in health context.
    # We detect explicit "Patient Name: John Smith" or "Patient: Mr. Smith"
    # patterns only. Requires a colon separator to avoid false positives on
    # sentences like "The patient has HIV" (no colon after patient/pt).
    # Name parts are case-SENSITIVE ([A-Z][a-z]+) to avoid matching any word.
    PHIPattern(
        name='Patient Name in Health Context',
        category='HIPAA Identity Linkage',
        pattern=re.compile(
            # "Patient Name: Mr. John Smith" or "Patient: John Smith"
            r'(?i:Patient(?:\s+Name)?)\s*[:=]\s*'
            r'(?:(?:Mr|Mrs|Ms|Dr)\.?\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+|'
            # "Pt Name: John Smith"
            r'(?i:Pt\s+Name)\s*[:=]\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+|'
            # "Patient DOB:", "Patient SSN:", "Patient MRN:" — data linkage
            r'(?i:Patient)\s+(?:DOB|SSN|MRN)\s*[:=]'
        ),
        severity='CRITICAL',
        requires_context=False
    ),
]


# ---------------------------------------------------------------------------
# Context-check: does surrounding text confirm a specific person?
# ---------------------------------------------------------------------------

def _has_personal_context(text: str, start: int, end: int) -> bool:
    """Check if match at position [start:end] is linked to a specific person."""
    lo = max(0, start - CONTEXT_WINDOW)
    hi = min(len(text), end + CONTEXT_WINDOW)
    window = text[lo:hi]
    return bool(PERSONAL_CONTEXT_PATTERNS.search(window))


def _has_health_context(text: str, start: int, end: int) -> bool:
    """Check if match at [start:end] is within a healthcare/clinical context."""
    lo = max(0, start - CONTEXT_WINDOW)
    hi = min(len(text), end + CONTEXT_WINDOW)
    return bool(HEALTH_CONTEXT_SIGNALS.search(text[lo:hi]))


# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------

def _mask_value(value: str, keep_chars: int = 2) -> str:
    """Mask a detected PHI value, keeping only leading characters."""
    if len(value) <= keep_chars:
        return '*' * len(value)
    return value[:keep_chars] + '*' * (len(value) - keep_chars)


def _apply_mask(text: str, start: int, end: int, replacement: str) -> str:
    """Return text with the span [start:end] replaced."""
    return text[:start] + replacement + text[end:]


# ---------------------------------------------------------------------------
# Health context signal detector
# Used to validate claim numbers, Rule B (PII in health context), etc.
# ---------------------------------------------------------------------------
HEALTH_CONTEXT_SIGNALS = re.compile(
    r'\b(diagnos\w+|admitted|discharged|prescribed|prescription|'
    r'biopsy|surgery|chemotherapy|chemo\b|radiation\s+therapy|dialysis|'
    r'hospital|clinic\b|ICU\b|ER\b|ED\b|emergency\s+(?:room|department)|'
    r'medical\s+(?:record|chart|history)|lab\s+(?:report|result|value)|'
    r'imaging|radiology|pathology|'
    r'prior\s+auth(?:orization)?|copay|deductible|EOB\b|reimbursement|'
    r'health\s+(?:plan|insurance)|pharmacy\s+benefit|insurance\s+claim|'
    r'specimen|accession|urinalysis|CT\s+scan|MRI\b|X[-\s]?ray|PET\s+scan|'
    r'ultrasound|mammogram|'
    r'disorder\b|disease\b|syndrome\b|infection\b|injury\b|fracture\b|'
    r'wound\b|trauma\b|cancer\b|tumor\b|mass\b|lesion\b|'
    r'diabetes|hypertension|HIV\b|AIDS\b|depression\b|anxiety\b|asthma\b|'
    r'COPD\b|heart\s+failure|stroke\b|seizure\b|miscarriage\b|'
    r'telehealth|telemedicine|refill\b|overdose\b|transplant\b|'
    r'treatment\b|therapy\b|procedure\b|operation\b|'
    r'test\s+result|vital\s+signs|'
    r'knee\s+surgery|hip\s+surgery|back\s+surgery|heart\s+surgery|'
    r'physical\s+therapy|occupational\s+therapy|'
    r'outpatient|inpatient|discharge\s+summary|progress\s+note|'
    r'referral\b|consultation\b|follow[-\s]?up\s+(?:visit|appointment)|'
    r'oncology|cardiology|neurology|psychiatry|orthopedic|'
    r'pathology\s+report|lab\s+order|lab\s+work|blood\s+work)\b',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# De-identification / non-PHI suppressors
# When clearly present with no contradicting real-person linkage, suppress.
# ---------------------------------------------------------------------------
DEIDENT_SUPPRESSORS = re.compile(
    r'\b(de[-\s]?identified|anonymized|anonymised|aggregate\s+only|'
    r'synthetic\s+(?:patient|data|record|example)|'
    r'fictional\s+(?:patient|example|record|data)|'
    r'example\s+(?:MRN|patient|data|record|case)|'
    r'dummy\s+(?:data|patient|record)|'
    r'population[-\s]?level\s+(?:data|analysis|statistics)|'
    r'counts?\s+only|statistics\s+only|'
    r'hypothetical\s+(?:patient|example|case)|'
    r'mock\s+(?:data|patient|record|example)|'
    r'sample\s+(?:data|patient)|'
    r'not\s+(?:a\s+)?real\s+patient|no\s+real\s+(?:patient|data))\b',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Rule B — generic identifiers that become PHI in healthcare context
# ---------------------------------------------------------------------------
_EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z]{2,}\b',
    re.IGNORECASE
)
_PHONE_RE = re.compile(
    r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'
)


# ---------------------------------------------------------------------------
# Rule A — claim number and prior authorization (require health context)
# ---------------------------------------------------------------------------
_CLAIM_RE = re.compile(
    r'\bClaim\s+(?:No|Number|#|ID)?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|'
    r'\bInsurance\s+Claim\s+(?:No|Number|#)?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|'
    r'\bClaim\s+#\s*([A-Z0-9][A-Z0-9-]{3,14})\b',
    re.IGNORECASE
)
_PRIOR_AUTH_RE = re.compile(
    r'\bPrior\s+Auth(?:orization)?(?:\s+(?:No|Number|#|ID))?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|'
    r'\bPA\s+(?:No|Number|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|'
    r'\bPre[-\s]?Auth(?:orization)?(?:\s+(?:No|Number|#))?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b',
    re.IGNORECASE
)
# Bare "prior authorization" phrase — inherently a healthcare term, flag if personal context
_PRIOR_AUTH_PHRASE_RE = re.compile(
    r'\bprior\s+auth(?:orization)?\b',
    re.IGNORECASE
)
# Subscriber/beneficiary bare number — requires health context
_SUBSCRIBER_BARE_RE = re.compile(
    r'\bSubscriber\s+(\d{4,12})\b',
    re.IGNORECASE
)
_BENEFICIARY_BARE_RE = re.compile(
    r'\bBeneficiary\s+(\d{4,12})\b',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Rule C — proper name + health event narrative
# Detects "Jane Doe had a miscarriage" / "John Smith was diagnosed with..."
# Case-sensitive name parts intentional — Title Case only, avoids "Blood Pressure"
# ---------------------------------------------------------------------------
_NAME_HEALTH_EVENT_RE = re.compile(
    # "Name was/had/is [health event]"
    r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+'
    r'(?:was|were|has|had|is|have|will\s+be)\s+'
    r'(?:diagnosed\s+with|admitted\s+(?:for|to|with)|treated\s+for|'
    r'prescribed|hospitalized|discharged|referred\s+for|tested\s+positive|'
    r'positive\s+for|scheduled\s+for\s+(?:surgery|biopsy|procedure|chemo)|'
    r'recovering\s+from|suffering\s+from)|'
    # "Name had a [health event noun]"
    r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:had|has|suffered|experienced)\s+'
    r'(?:a\s+)?(?:miscarriage|stroke|heart\s+attack|seizure|overdose|'
    r'surgery|biopsy|transplant|relapse|abortion|stillbirth)|'
    # "Name's [medical record/document]"
    r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\'s?\s+'
    r'(?:pathology\s+report|biopsy\s+(?:result|report)|lab\s+(?:result|report)|'
    r'medical\s+record|MRI|CT\s+scan|X[-\s]?ray|diagnosis|prescription|'
    r'health\s+record|insurance\s+claim|radiology\s+report|test\s+results?)'
)

# Common two-word Title Case terms that are NOT person names — excluded from Rule C
_NON_PERSON_NAMES = frozenset({
    'Blood Pressure', 'Heart Rate', 'Blood Sugar', 'Blood Type', 'Blood Count',
    'Blood Work', 'Chest Pain', 'Heart Attack', 'Type One', 'Type Two',
    'Stage One', 'Stage Two', 'Stage Three', 'Stage Four', 'United States',
    'New York', 'Los Angeles', 'Health Plan', 'Health Care', 'Health Record',
    'Medical Record', 'Patient Care', 'Vital Signs', 'Lab Result', 'Lab Report',
    'Test Result', 'North America', 'Mental Health', 'Public Health',
    'Brain Tumor', 'Lung Cancer', 'Breast Cancer', 'Skin Cancer',
})


# ---------------------------------------------------------------------------
# PHI Detector class
# ---------------------------------------------------------------------------

class PHIDetector:
    """
    HIPAA PHI detector.

    Covers all 18 HIPAA Safe Harbor identifier categories that are NOT
    already handled by the pii-detector skill, plus health context patterns
    (diagnoses, medications, lab results, vital signs, clinical notes).
    """

    def __init__(self):
        self.admin_patterns = ADMIN_PHI_PATTERNS
        self.condition_patterns = CONDITION_PATTERNS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> Dict[str, Any]:
        """
        Detect all PHI in the provided text.

        Args:
            text: The prompt or document to scan.

        Returns:
            {
                'findings': list of finding dicts,
                'count': int,
                'has_critical': bool,
                'has_high': bool,
                'categories_detected': list[str],
                'phi_types': dict[str, int],
                'masked_text': str,
                'summary': str
            }
        """
        findings = []
        masked_text = text
        offset = 0  # tracks position shift after masking substitutions

        # ── Pre-step: De-identification suppressor check ──────────────────
        # If the text is explicitly marked as de-identified/synthetic/test
        # data, suppress condition-based findings (admin identifiers still
        # fire since they shouldn't appear even in de-identified records).
        is_deidentified = bool(DEIDENT_SUPPRESSORS.search(text))

        # ── Step 1: Administrative / code-based PHI ──────────────────────
        for phi_pat in self.admin_patterns:
            for match in phi_pat.pattern.finditer(text):
                # Extract first non-None group as the actual value
                matched_value = match.group(0)
                extracted = next(
                    (g for g in match.groups() if g is not None),
                    matched_value
                )

                # Context check if required
                if phi_pat.requires_context:
                    if not _has_personal_context(text, match.start(), match.end()):
                        continue

                masked = _mask_value(extracted)
                masked_full = matched_value.replace(extracted, masked)

                findings.append({
                    'category':    phi_pat.category,
                    'type':        phi_pat.name,
                    'severity':    phi_pat.severity,
                    'value':       matched_value,
                    'masked_value': masked_full,
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      f'HIPAA PHI: {phi_pat.name} detected'
                })

                # Apply mask to masked_text
                adj_start = match.start() + offset
                adj_end   = match.end()   + offset
                masked_text = _apply_mask(masked_text, adj_start, adj_end,
                                          f'[{phi_pat.name.upper()}]')
                offset += len(f'[{phi_pat.name.upper()}]') - (match.end() - match.start())

        # ── Step 2: ICD-10 code detection (with nearby label check) ─────
        # Track codes already captured by step 1 admin patterns to avoid dups.
        already_found_codes = set()
        for f in findings:
            if 'ICD' in f.get('type', ''):
                # Extract the raw code value from the full matched string
                m = ICD10_CODE_RE.search(f.get('value', ''))
                if m:
                    already_found_codes.add(m.group(1).upper())

        for match in ICD10_CODE_RE.finditer(text):
            code = match.group(1)
            if code.upper() in already_found_codes:
                continue  # skip — already captured by admin pattern in step 1
            # Require ICD label in a 200-char window, OR "Dx" / "diagnosis" nearby
            lo = max(0, match.start() - 200)
            hi = min(len(text), match.end() + 50)
            window = text[lo:hi]
            if ICD10_LABEL_RE.search(window):
                already_found_codes.add(code.upper())
                findings.append({
                    'category': 'Clinical Code',
                    'type':     'ICD-10 Diagnosis Code (standalone)',
                    'severity': 'HIGH',
                    'value':    code,
                    'masked_value': '[ICD-CODE]',
                    'position': match.start(),
                    'context':  self._extract_context_snippet(
                                    text, match.start(), match.end()),
                    'reason':   'HIPAA PHI: ICD-10 diagnosis code identifying patient condition'
                })

        # ── Step 3: Condition / diagnosis plaintext ──────────────────────
        if not is_deidentified:
            for pattern, category, severity in self.condition_patterns:
                for match in pattern.finditer(text):
                    # CRITICAL conditions (mental health, HIV, SUD, STI,
                    # genetics, reproductive, cancer) are flagged regardless
                    # of personal context — they almost never appear in prompts
                    # without referring to a specific individual.
                    # HIGH conditions (serious chronic) require personal context
                    # to avoid false positives on educational/general queries.
                    if severity == 'HIGH':
                        if not _has_personal_context(text, match.start(), match.end()):
                            continue
                    findings.append({
                        'category': 'Health Condition Disclosure',
                        'type':     category,
                        'severity': severity,
                        'value':    match.group(0),
                        'masked_value': f'[{category.upper().replace(" ", "_")}]',
                        'position': match.start(),
                        'context':  self._extract_context_snippet(
                                        text, match.start(), match.end()),
                        'reason':   (
                            f'HIPAA PHI: Sensitive health condition '
                            f'({category}) — disclosure requires patient consent'
                        )
                    })

        # ── Step 4: Medication + dosage (prescription context) ───────────
        med_findings = self._detect_medications(text)
        findings.extend(med_findings)

        # ── Step 5: Rule A extras + Rule B (health-context linked IDs) ───
        # Claim numbers — healthcare context validates these as PHI
        for match in _CLAIM_RE.finditer(text):
            if _has_health_context(text, match.start(), match.end()):
                findings.append({
                    'category':    'Health Insurance Identifier',
                    'type':        'Health Insurance Claim Number',
                    'severity':    'HIGH',
                    'value':       match.group(0),
                    'masked_value': '[CLAIM_NUMBER]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      'HIPAA PHI: Insurance claim number linked to healthcare'
                })

        # Prior authorization numbers
        for match in _PRIOR_AUTH_RE.finditer(text):
            findings.append({
                'category':    'Health Insurance Identifier',
                'type':        'Prior Authorization Number',
                'severity':    'HIGH',
                'value':       match.group(0),
                'masked_value': '[PRIOR_AUTH_NUMBER]',
                'position':    match.start(),
                'context':     self._extract_context_snippet(
                                   text, match.start(), match.end()),
                'reason':      'HIPAA PHI: Prior authorization number is a health plan identifier'
            })

        # Bare prior authorization phrase with personal context (no number)
        for match in _PRIOR_AUTH_PHRASE_RE.finditer(text):
            if _has_personal_context(text, match.start(), match.end()):
                # Only flag if not already captured by numbered pattern above
                if not any(f['position'] == match.start() for f in findings):
                    findings.append({
                        'category':    'Health Insurance Identifier',
                        'type':        'Prior Authorization (Health Context)',
                        'severity':    'MEDIUM',
                        'value':       match.group(0),
                        'masked_value': '[PRIOR_AUTH]',
                        'position':    match.start(),
                        'context':     self._extract_context_snippet(
                                           text, match.start(), match.end()),
                        'reason':      'HIPAA PHI: Prior authorization is an inherently healthcare term linked to a patient'
                    })

        # Subscriber bare number — requires health context
        for match in _SUBSCRIBER_BARE_RE.finditer(text):
            if _has_health_context(text, match.start(), match.end()):
                findings.append({
                    'category':    'Health Insurance Identifier',
                    'type':        'Health Plan Subscriber Number',
                    'severity':    'HIGH',
                    'value':       match.group(0),
                    'masked_value': '[SUBSCRIBER_NUMBER]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      'HIPAA PHI: Subscriber number linked to healthcare context'
                })

        # Beneficiary bare number — requires health context
        for match in _BENEFICIARY_BARE_RE.finditer(text):
            if _has_health_context(text, match.start(), match.end()):
                findings.append({
                    'category':    'Health Insurance Identifier',
                    'type':        'Health Plan Beneficiary Number (bare)',
                    'severity':    'HIGH',
                    'value':       match.group(0),
                    'masked_value': '[BENEFICIARY_NUMBER]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      'HIPAA PHI: Beneficiary number linked to healthcare context'
                })

        # Rule B: Email in healthcare context
        for match in _EMAIL_RE.finditer(text):
            if _has_health_context(text, match.start(), match.end()):
                findings.append({
                    'category':    'Health-Linked Generic Identifier',
                    'type':        'Email Address in Healthcare Context',
                    'severity':    'HIGH',
                    'value':       match.group(0),
                    'masked_value': '[EMAIL_IN_HEALTH_CONTEXT]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      'HIPAA PHI Rule B: Email address linked to healthcare context'
                })

        # Rule B: Phone in healthcare context
        for match in _PHONE_RE.finditer(text):
            if _has_health_context(text, match.start(), match.end()):
                findings.append({
                    'category':    'Health-Linked Generic Identifier',
                    'type':        'Phone Number in Healthcare Context',
                    'severity':    'HIGH',
                    'value':       match.group(0),
                    'masked_value': '[PHONE_IN_HEALTH_CONTEXT]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      'HIPAA PHI Rule B: Phone number linked to healthcare context'
                })

        # ── Step 6: Rule C — proper name + health event narrative ────────
        for match in _NAME_HEALTH_EVENT_RE.finditer(text):
            # Extract whichever capture group matched (alternation)
            name = next((g for g in match.groups() if g is not None), None)
            if name and name not in _NON_PERSON_NAMES:
                findings.append({
                    'category':    'Health-Linked Identity',
                    'type':        'Person Name with Health Event',
                    'severity':    'HIGH',
                    'value':       name,
                    'masked_value': '[PERSON_NAME_HEALTH_EVENT]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      'HIPAA PHI Rule C: Person identified by name linked to a health event'
                })

        # ── Step 7: De-duplicate (same position, same type) ─────────────
        findings = self._deduplicate(findings)

        # ── Build summary output ─────────────────────────────────────────
        phi_types: Dict[str, int] = {}
        categories_detected: List[str] = []
        has_critical = False
        has_high = False

        for f in findings:
            phi_types[f['type']] = phi_types.get(f['type'], 0) + 1
            if f['category'] not in categories_detected:
                categories_detected.append(f['category'])
            if f['severity'] == 'CRITICAL':
                has_critical = True
            if f['severity'] == 'HIGH':
                has_high = True

        return {
            'findings':            findings,
            'count':               len(findings),
            'has_critical':        has_critical,
            'has_high':            has_high,
            'categories_detected': categories_detected,
            'phi_types':           phi_types,
            'masked_text':         masked_text,
            'summary':             self._build_summary(findings, phi_types)
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_medications(self, text: str) -> List[Dict[str, Any]]:
        """Detect prescription medication + dosage combos linked to a person."""
        results = []
        for match in MEDICATION_CLASS_RE.finditer(text):
            drug = match.group(0)
            lo = max(0, match.start() - 150)
            hi = min(len(text), match.end() + 150)
            window = text[lo:hi]

            # Must have dosage OR prescription context nearby to be PHI
            has_dose    = bool(DOSAGE_RE.search(window))
            has_rx_ctx  = bool(PRESCRIPTION_CONTEXT_RE.search(window))
            has_patient = bool(PERSONAL_CONTEXT_PATTERNS.search(window))

            if (has_dose or has_rx_ctx) and has_patient:
                results.append({
                    'category':    'Prescription Medication',
                    'type':        'Medication with Dosage / Patient Context',
                    'severity':    'HIGH',
                    'value':       drug,
                    'masked_value': '[MEDICATION]',
                    'position':    match.start(),
                    'context':     self._extract_context_snippet(
                                       text, match.start(), match.end()),
                    'reason':      (
                        'HIPAA PHI: Prescription medication linked to a patient '
                        'constitutes protected health information'
                    )
                })
        return results

    def _extract_context_snippet(self, text: str, start: int, end: int,
                                  window: int = 60) -> str:
        """Return a short context snippet around the match (no PII in snippet)."""
        lo = max(0, start - window)
        hi = min(len(text), end + window)
        snippet = text[lo:hi].strip()
        # Replace newlines for readability
        snippet = re.sub(r'\s+', ' ', snippet)
        return f'...{snippet}...' if len(snippet) < len(text) else snippet

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings at the same position."""
        seen = set()
        unique = []
        for f in findings:
            key = (f['position'], f['type'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        # Sort by position
        unique.sort(key=lambda x: x['position'])
        return unique

    def _build_summary(self, findings: List[Dict[str, Any]],
                        phi_types: Dict[str, int]) -> str:  # noqa: ARG002
        """Build a human-readable summary."""
        if not findings:
            return 'No PHI detected.'

        critical = [f for f in findings if f['severity'] == 'CRITICAL']
        high     = [f for f in findings if f['severity'] == 'HIGH']
        medium   = [f for f in findings if f['severity'] == 'MEDIUM']

        parts = [f'PHI detected: {len(findings)} item(s).']
        if critical:
            parts.append(
                f'CRITICAL ({len(critical)}): '
                + ', '.join({f["type"] for f in critical})
            )
        if high:
            parts.append(
                f'HIGH ({len(high)}): '
                + ', '.join({f["type"] for f in high})
            )
        if medium:
            parts.append(
                f'MEDIUM ({len(medium)}): '
                + ', '.join({f["type"] for f in medium})
            )
        return ' | '.join(parts)


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    import json

    # Ensure UTF-8 output on Windows (prevents crash on Unicode chars like μ)
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        print('Usage: python phi_detector.py "<text>"')
        print('       python phi_detector.py --example')
        sys.exit(1)

    if sys.argv[1] == '--example':
        examples = [
            # Administrative code example
            'Patient was admitted on 03/15/2024, NPI: 1234567890, '
            'Dx Code: J18.9 (pneumonia). Rx#: 123456789. DEA: AB1234567.',

            # Sensitive condition example
            'The patient has HIV-positive status and is on antiretroviral therapy. '
            'CD4 count: 420 cells/μL, viral load undetectable.',

            # Mental health example
            'Patient presented with major depressive disorder and PTSD. '
            'Prescribed sertraline 50 mg daily. PMH: bipolar disorder type II.',

            # Lab results with clinical context
            'HbA1c: 8.2%, fasting glucose: 187 mg/dL. '
            'Patient is a 72-year-old male with type 2 diabetes.',

            # No PHI
            'How do I reset my password? I forgot it yesterday.',
        ]

        detector = PHIDetector()
        for i, text in enumerate(examples, 1):
            print(f'\n=== Example {i} ===')
            print(f'Input: {text[:80]}...' if len(text) > 80 else f'Input: {text}')
            result = detector.detect(text)
            print(f'PHI count: {result["count"]}')
            print(f'Summary: {result["summary"]}')
            if result['findings']:
                print('Findings:')
                for f in result['findings']:
                    print(f'  [{f["severity"]}] {f["type"]}: {f["masked_value"]}')
    else:
        text = sys.argv[1]
        detector = PHIDetector()
        result = detector.detect(text)
        print(json.dumps(result, indent=2, default=str))
