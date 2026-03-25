/**
 * PawSec PHI Detector (browser port of phi_detector.py)
 *
 * Detects HIPAA Protected Health Information (PHI) with ZERO OVERLAP
 * against pii_detector.js (which covers SSN, email, phone, passport,
 * DOB, credit card, bank account, MRN, insurance_id, address, IP, MAC).
 *
 * This detector covers:
 *   - Medical administrative codes (NPI, DEA, CPT, ICD-10, HCPCS, NDC, UDI)
 *   - Health plan identifiers (beneficiary numbers, group IDs, Rx numbers, lab accession)
 *   - Health context patterns: diagnoses, medications, lab results, vital signs
 *   - Extra-sensitive PHI: mental health, HIV/AIDS, substance abuse, genetic, reproductive
 *   - HIPAA-specific temporal: admission/discharge dates, death dates, age > 89
 *   - Rule B: generic identifiers (email/phone) in healthcare context
 *   - Rule C: person name + health event narrative
 *
 * Returns:
 *   detected            — true if any PHI found
 *   findings            — array of { category, type, severity, value, masked_value, position, context, reason }
 *   count               — total findings
 *   has_critical        — any CRITICAL-severity findings
 *   has_high            — any HIGH-severity findings
 *   categories_detected — list of unique category strings
 *   risk_level          — SAFE / MEDIUM / HIGH / CRITICAL
 *   masked_text         — text with PHI values replaced by [TYPE] tags
 */

// ── Context window ─────────────────────────────────────────────────────────
const CONTEXT_WINDOW = 250;

// ── Personal/patient context markers ──────────────────────────────────────
const PERSONAL_CONTEXT_RE = /\b(patient|pt\b|client|resident|member|subject|participant|individual|person|name|dob|born|age|gender|sex|male|female|he|she|they|his|her|their|i have|i am|i was|my|admitted|discharged|presenting|diagnosed|treated|prescribed|referred|consult(?:ed)?|encounter|visit|case|record|chart|mr\b|mrs\b|ms\b|dr\b)\b/gi;

// ── Health context signals ─────────────────────────────────────────────────
const HEALTH_CONTEXT_RE = /\b(diagnos\w+|admitted|discharged|prescribed|prescription|biopsy|surgery|chemotherapy|chemo\b|radiation\s+therapy|dialysis|hospital|clinic\b|ICU\b|ER\b|ED\b|emergency\s+(?:room|department)|medical\s+(?:record|chart|history)|lab\s+(?:report|result|value)|imaging|radiology|pathology|prior\s+auth(?:orization)?|copay|deductible|EOB\b|reimbursement|health\s+(?:plan|insurance)|pharmacy\s+benefit|insurance\s+claim|specimen|accession|urinalysis|CT\s+scan|MRI\b|X[-\s]?ray|PET\s+scan|ultrasound|mammogram|disorder\b|disease\b|syndrome\b|infection\b|injury\b|fracture\b|wound\b|trauma\b|cancer\b|tumor\b|mass\b|lesion\b|diabetes|hypertension|HIV\b|AIDS\b|depression\b|anxiety\b|asthma\b|COPD\b|heart\s+failure|stroke\b|seizure\b|miscarriage\b|telehealth|telemedicine|refill\b|overdose\b|transplant\b|treatment\b|therapy\b|procedure\b|operation\b|test\s+result|vital\s+signs|knee\s+surgery|hip\s+surgery|back\s+surgery|heart\s+surgery|physical\s+therapy|occupational\s+therapy|outpatient|inpatient|discharge\s+summary|progress\s+note|referral\b|consultation\b|follow[-\s]?up\s+(?:visit|appointment)|oncology|cardiology|neurology|psychiatry|orthopedic|pathology\s+report|lab\s+order|lab\s+work|blood\s+work)\b/gi;

// ── De-identification suppressors ─────────────────────────────────────────
const DEIDENT_RE = /\b(de[-\s]?identified|anonymized|anonymised|aggregate\s+only|synthetic\s+(?:patient|data|record|example)|fictional\s+(?:patient|example|record|data)|example\s+(?:MRN|patient|data|record|case)|dummy\s+(?:data|patient|record)|population[-\s]?level\s+(?:data|analysis|statistics)|counts?\s+only|statistics\s+only|hypothetical\s+(?:patient|example|case)|mock\s+(?:data|patient|record|example)|sample\s+(?:data|patient)|not\s+(?:a\s+)?real\s+patient|no\s+real\s+(?:patient|data))\b/gi;

// ── ICD-10 patterns ────────────────────────────────────────────────────────
const ICD10_CODE_RE  = /\b([A-Z]\d{2}(?:\.\d{1,4})?)\b/gi;
const ICD10_LABEL_RE = /\b(ICD[-\s]?10|ICD[-\s]?9|diagnosis code|dx code|diagnostic code|primary dx|secondary dx|admitting dx|discharge dx|billable code|condition code)\b/gi;

// ── Condition patterns (CRITICAL and HIGH sensitivity) ────────────────────
const CONDITION_PATTERNS = [
  {
    re: /\b(major\s+depressive\s+disorder|clinical\s+depression|severe\s+depression|acute\s+depression|depressive\s+episode|treatment[- ]resistant\s+depression|bipolar\s+disorder|bipolar\s+[I]+|bipolar\s+diagnosis|manic\s+episode|manic[- ]depressive|schizophrenia|schizoaffective|acute\s+psychosis|psychotic\s+break|psychosis|psychotic\s+episode|post[- ]traumatic\s+stress|PTSD|obsessive[- ]compulsive|OCD|panic\s+disorder|generalized\s+anxiety\s+disorder|borderline\s+personality|antisocial\s+personality|eating\s+disorder|anorexia\s+nervosa|bulimia\s+nervosa|binge\s+eating|ADHD|attention\s+deficit|autism\s+spectrum|ASD|intellectual\s+disability|dementia|Alzheimer'?s|suicidal\s+ideation|self[- ]harm|self[- ]injury|psychiatric\s+hospitalization|inpatient\s+psych|mental\s+health\s+diagnosis|involuntary\s+hold|5150|Baker\s+Act)\b/gi,
    category: 'Mental Health Condition',
    severity: 'CRITICAL',
  },
  {
    re: /\b(substance\s+use\s+disorder|SUD\b|opioid\s+use\s+disorder|OUD\b|alcohol\s+use\s+disorder|AUD\b|drug\s+dependence|drug\s+addiction|opioid\s+dependence|heroin\s+dependence|methamphetamine\s+use|cocaine\s+dependence|benzodiazepine\s+dependence|methadone\s+treatment|buprenorphine\s+treatment|suboxone\s+treatment|naltrexone\s+treatment|MAT\s+program|medication[- ]assisted\s+treatment|in\s+recovery\s+from|rehab(?:ilitation)?\s+program|detox(?:ification)?\s+program|narcotics\s+anonymous|AA\s+program|alcoholism\s+diagnosis|alcohol\s+dependence|overdose\s+(?:treatment|recovery|episode|event|history)|drug\s+overdose|opioid\s+overdose|naloxone\s+administered)\b/gi,
    category: 'Substance Use Disorder',
    severity: 'CRITICAL',
  },
  {
    re: /\b(HIV[- ]positive|HIV\+|human\s+immunodeficiency\s+virus|AIDS\b|acquired\s+immunodeficiency\s+syndrome|CD4\s+count|viral\s+load\s+undetectable|antiretroviral\s+therapy|ART\s+regimen|PrEP\s+user|post[- ]exposure\s+prophylaxis|PEP\s+treatment|HIV\s+diagnosis|HIV\s+status|HIV\s+test\s+result|HIV\s+infected)\b/gi,
    category: 'HIV/AIDS Status',
    severity: 'CRITICAL',
  },
  {
    re: /\b(gonorrhea|chlamydia|syphilis|herpes\s+simplex|HSV[-\s]?[12]|genital\s+herpes|genital\s+warts|HPV\s+diagnosis|hepatitis\s+[BC]\s+diagnosis|Hep\s+[BC]\s+positive|sexually\s+transmitted\s+infection|STI\s+diagnosis|STD\s+diagnosis|trichomoniasis|bacterial\s+vaginosis\s+diagnosis)\b/gi,
    category: 'Sexually Transmitted Infection',
    severity: 'CRITICAL',
  },
  {
    re: /\b(BRCA[12]?\s+(?:positive|mutation|variant)|genetic\s+test\s+result|genetic\s+mutation\s+found|hereditary\s+cancer\s+syndrome|Lynch\s+syndrome|Huntington'?s\s+disease|genetic\s+disorder\s+diagnosis|chromosomal\s+abnormality|Down\s+syndrome\s+diagnosis|Trisomy\s+\d+|cystic\s+fibrosis\s+gene|CFTR\s+mutation|sickle\s+cell\s+trait|sickle\s+cell\s+disease|familial\s+hypercholesterolemia|genetic\s+carrier\s+status|pharmacogenomic\s+test|DNA\s+test\s+result|exome\s+sequencing\s+result|genome\s+sequencing\s+result)\b/gi,
    category: 'Genetic Information',
    severity: 'CRITICAL',
  },
  {
    re: /\b(pregnant\s+with|current\s+pregnancy|gestational\s+age|estimated\s+due\s+date|EDD\b|weeks\s+gestation|gravida|para\s+\d|G\d+P\d+|abortion\s+procedure|termination\s+of\s+pregnancy|miscarriage|pregnancy\s+loss|spontaneous\s+abortion|ectopic\s+pregnancy|IVF\s+treatment|in\s+vitro\s+fertilization|fertility\s+treatment|infertility\s+diagnosis|IUI\s+procedure|egg\s+retrieval|sperm\s+analysis\s+result|tubal\s+ligation|vasectomy\s+record|contraceptive\s+implant|reproductive\s+health\s+record)\b/gi,
    category: 'Reproductive Health',
    severity: 'CRITICAL',
  },
  {
    re: /\b(cancer\s+diagnosis|malignant\s+neoplasm|carcinoma\s+of|adenocarcinoma|squamous\s+cell\s+carcinoma|basal\s+cell\s+carcinoma|lymphoma\s+diagnosis|leukemia\s+diagnosis|melanoma\s+diagnosis|stage\s+[I]{1,3}V?\s+cancer|stage\s+[1-4]\s+cancer|metastatic\s+cancer|oncology\s+patient|chemotherapy\s+patient|radiation\s+therapy\s+for\s+cancer|tumor\s+marker\s+result|PSA\s+elevated|CA[- ]?125\s+level|CA[- ]?19[- ]?9\s+level|CEA\s+level|biopsy\s+result\s+malignant|pathology\s+report\s+malignant)\b/gi,
    category: 'Cancer Diagnosis',
    severity: 'CRITICAL',
  },
  {
    re: /\b(type\s+[12]\s+diabetes|diabetes\s+mellitus\s+type\s+[12]|T[12]DM\b|insulin[- ]dependent\s+diabetes|end[- ]stage\s+renal\s+disease|ESRD\b|chronic\s+kidney\s+disease\s+stage\s+[1-5]|CKD\s+stage\s+[1-5]|congestive\s+heart\s+failure|CHF\s+diagnosis|coronary\s+artery\s+disease|CAD\s+diagnosis|myocardial\s+infarction|heart\s+attack\s+history|stroke\s+history|CVA\s+history|COPD\s+diagnosis|emphysema\s+diagnosis|cirrhosis\s+diagnosis|hepatic\s+failure|liver\s+failure\s+diagnosis|seizure\s+disorder|epilepsy\s+diagnosis|multiple\s+sclerosis|MS\s+diagnosis|Parkinson'?s\s+disease|ALS\b|amyotrophic\s+lateral\s+sclerosis|rheumatoid\s+arthritis\s+diagnosis|lupus\s+diagnosis|SLE\b|IBD\s+diagnosis|Crohn'?s\s+disease\s+diagnosis|ulcerative\s+colitis\s+diagnosis)\b/gi,
    category: 'Serious Chronic Condition',
    severity: 'HIGH',
  },
];

// ── Medication class (controlled/prescription drugs) ──────────────────────
const MEDICATION_CLASS_RE = /\b(oxycodone|oxycontin|hydrocodone|vicodin|fentanyl|morphine|codeine|buprenorphine|suboxone|methadone|tramadol|dilaudid|hydromorphone|percocet|norco|xanax|alprazolam|valium|diazepam|klonopin|clonazepam|ativan|lorazepam|ambien|zolpidem|adderall|amphetamine|ritalin|methylphenidate|concerta|vyvanse|lisdexamfetamine|dexedrine|lithium\s+carbonate|quetiapine|seroquel|olanzapine|zyprexa|risperidone|risperdal|aripiprazole|abilify|clozapine|clozaril|haloperidol|haldol|paliperidone|invega|ziprasidone|geodon|sertraline|zoloft|fluoxetine|prozac|paroxetine|paxil|escitalopram|lexapro|citalopram|celexa|venlafaxine|effexor|duloxetine|cymbalta|bupropion|wellbutrin|mirtazapine|remeron|warfarin|coumadin|heparin|enoxaparin|lovenox|apixaban|eliquis|rivaroxaban|xarelto|dabigatran|pradaxa|clopidogrel|plavix|atorvastatin|lipitor|simvastatin|zocor|rosuvastatin|crestor|metformin|glucophage|insulin\s+(?:glargine|lispro|aspart|detemir|degludec|NPH|regular)|humalog|lantus|novolog|levemir|tresiba|lisinopril|enalapril|ramipril|metoprolol|lopressor|atenolol|amlodipine|norvasc|losartan|cozaar|valsartan|diovan|levothyroxine|synthroid|prednisone|prednisolone|dexamethasone|azithromycin|amoxicillin|ciprofloxacin|doxycycline|vancomycin|tacrolimus|prograf|cyclosporine|mycophenolate|cellcept|imatinib|gleevec|erlotinib|tarceva|bevacizumab|avastin|trastuzumab|herceptin|rituximab|rituxan|pembrolizumab|keytruda|nivolumab|opdivo|exemestane|aromasin|tamoxifen|anastrozole|arimidex|leuprolide|lupron|finasteride|dutasteride)\b/gi;

const DOSAGE_RE = /\b\d+(?:\.\d+)?\s*(?:mg|mcg|mEq|units?|IU|ml|mL|g|mmol)\b(?:\/(?:day|week|month|dose|kg|hr|min))?/gi;
const PRESCRIPTION_CONTEXT_RE = /\b(prescribed\s+\w|taking\s+\w|on\s+a\s+dose\s+of|dosage\s+of|dose:\s*\d|sig:\s*\w|dispense\s+#|quantity:\s*\d|refill|\d+\s*mg\s+(?:daily|twice|three\s+times|QD|BID|TID|QID)|po\s+\w|SL\s+\w|topical\s+\w|injection\s+of\s+\w)\b/gi;

// ── Administrative PHI patterns ────────────────────────────────────────────
const ADMIN_PHI_PATTERNS = [
  {
    name: 'National Provider Identifier (NPI)',
    category: 'Medical Provider Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bNPI[:\s#-]*([12]\d{9})\b|\bNational\s+Provider\s+ID[:\s#-]*([12]\d{9})\b|\bProvider\s+NPI[:\s#-]*([12]\d{9})\b/gi,
  },
  {
    name: 'DEA Registration Number',
    category: 'Medical Provider Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bDEA[:\s#-]*([A-Z]{2}\d{7})\b|\bDrug\s+Enforcement\s+(?:Admin|Administration)[:\s#-]*([A-Z]{2}\d{7})\b/gi,
  },
  {
    name: 'Health Plan Beneficiary Number',
    category: 'Health Insurance Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\b(?:Health\s+Plan\s+)?Beneficiary\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|\bMember\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|\bSubscriber\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|\bEnrollment\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b|\bPlan\s+Member\s+(?:No|Number|ID|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,14})\b/gi,
  },
  {
    name: 'Health Insurance Group Number',
    category: 'Health Insurance Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bGroup\s+(?:No|Number|ID|#|Policy(?:\s+No)?)[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|\bPolicy\s+Group[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|\bEmployer\s+Group\s+(?:No|Number|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b/gi,
  },
  {
    name: 'Prescription Number',
    category: 'Pharmacy Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bRx\s*(?:No|Number|#)[:\s#-]*(\d{6,12})\b|\bRx[:\s#]*(\d{6,12})\b|\bPrescription\s+(?:No|Number|#)[:\s#-]*(\d{6,12})\b|\bRx\s+ID[:\s#-]*(\d{6,12})\b/gi,
  },
  {
    name: 'Lab Accession Number',
    category: 'Laboratory Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bAccession\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|\bACC[:\s#-]*([A-Z]{0,3}[-]?\d{6,12})\b|\bSpecimen\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|\bLab\s+(?:No|Number|#|ID|Order)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|\bOrder\s+(?:No|Number|#)[:\s#-]*([A-Z]{0,2}[-]?\d{6,12})\b/gi,
  },
  {
    name: 'Radiology/Pathology Order Number',
    category: 'Diagnostic Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bRadiology\s+(?:Order|No|Number|#)[:\s#-]*([A-Z0-9]{6,14})\b|\bPathology\s+(?:Report|No|Number|#|ID)[:\s#-]*([A-Z0-9]{6,14})\b|\bImaging\s+(?:Order|No|Number)[:\s#-]*([A-Z0-9]{6,14})\b|\bPath\s+(?:No|Report\s+No)[:\s#-]*([A-Z0-9]{6,14})\b/gi,
  },
  {
    name: 'Medical Device Identifier (UDI)',
    category: 'Medical Device Identifier',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bUDI[:\s#-]*\(?01\)?[\s]*(\d{14})\b|\bDevice\s+(?:Serial|UDI|ID|#)[:\s#-]*([A-Z0-9]{8,20})\b|\bImplant\s+(?:Serial|ID|#)[:\s#-]*([A-Z0-9]{8,20})\b|\bPacemaker\s+(?:Serial|ID|#)[:\s#-]*([A-Z0-9]{6,16})\b|\bDefibrillator\s+(?:Serial|ID|#)[:\s#-]*([A-Z0-9]{6,16})\b/gi,
  },
  {
    name: 'CPT Procedure Code',
    category: 'Clinical Code',
    severity: 'MEDIUM',
    requiresContext: false,
    re: /\bCPT[:\s#-]*(\d{5})\b|\bProcedure\s+Code[:\s#-]*(\d{5})\b|\bProc\s+Code[:\s#-]*(\d{5})\b|\bService\s+Code[:\s#-]*([0-9]{5}[A-Z]?)\b/gi,
  },
  {
    name: 'HCPCS Level II Code',
    category: 'Clinical Code',
    severity: 'MEDIUM',
    requiresContext: false,
    re: /\bHCPCS[:\s#-]*([A-V]\d{4})\b|\bHCPC\s+Code[:\s#-]*([A-V]\d{4})\b|\bSupply\s+Code[:\s#-]*([A-V]\d{4})\b/gi,
  },
  {
    name: 'NDC Drug Code',
    category: 'Pharmacy Identifier',
    severity: 'MEDIUM',
    requiresContext: false,
    re: /\bNDC[:\s#-]*(\d{4,5}[-]\d{3,4}[-]\d{1,2})\b|\bNational\s+Drug\s+Code[:\s#-]*(\d{4,5}[-]\d{3,4}[-]\d{1,2})\b|\bNDC[:\s#-]*(\d{10,11})\b/gi,
  },
  {
    name: 'Clinical Trial ID',
    category: 'Research Identifier',
    severity: 'MEDIUM',
    requiresContext: false,
    re: /\b(NCT\d{8})\b|\bClinical\s+Trial\s+(?:No|Number|#|ID)[:\s#-]*(NCT\d{8})\b|\bTrial\s+Enrollment\s+(?:No|#)[:\s#-]*([A-Z0-9]{6,14})\b/gi,
  },
  {
    name: 'Medical Encounter Number',
    category: 'Medical Administrative',
    severity: 'HIGH',
    requiresContext: true,
    re: /\bEncounter\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|\bVisit\s+(?:No|Number|#|ID)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|\bAdmission\s+(?:No|Number|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b|\bCase\s+(?:No|Number|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{5,13})\b/gi,
  },
  {
    name: 'ICD-10 Diagnosis Code',
    category: 'Clinical Code',
    severity: 'HIGH',
    requiresContext: false,
    re: /\bICD[-\s]?10[-\s]?(?:CM|PCS)?[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|\bDx\s+Code[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|\bDiagnosis\s+Code[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|\bPrimary\s+Dx[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b|\bDischarge\s+Dx[:\s#-]*([A-Z]\d{2}(?:\.\d{1,4})?)\b/gi,
  },
  {
    name: 'Clinical Vital Signs',
    category: 'Clinical Measurement',
    severity: 'HIGH',
    requiresContext: true,
    re: /\b(?:BP|blood\s+pressure)[:\s]*(\d{2,3}\/\d{2,3})\s*mm\s*Hg\b|\b(?:HR|heart\s+rate|pulse)[:\s]*(\d{2,3})\s*bpm\b|\b(?:SpO2|oxygen\s+saturation|O2\s+sat)[:\s]*(\d{2,3})\s*%|\b(?:Temp|temperature)[:\s]*(\d{2,3}(?:\.\d)?)\s*[°]?[CF]\b|\b(?:RR|respiratory\s+rate)[:\s]*(\d{1,2})\s*(?:breaths?\/min|rpm)\b|\b(?:BMI)[:\s]*(\d{1,2}(?:\.\d{1,2})?)\s*(?:kg\/m2)?\b|\bWeight[:\s]*(\d{2,3}(?:\.\d)?)\s*(?:lbs?|kg)\b/gi,
  },
  {
    name: 'Laboratory Result',
    category: 'Clinical Measurement',
    severity: 'HIGH',
    requiresContext: true,
    re: /\b(?:HbA1c|A1C|hemoglobin\s+A1C)[:\s]*(\d{1,2}(?:\.\d)?)\s*%|\b(?:fasting\s+)?(?:blood\s+glucose|glucose)[:\s]*(\d{2,3})\s*mg\/dL\b|\b(?:PSA|prostate[- ]specific\s+antigen)[:\s]*(\d+(?:\.\d+)?)\s*ng\/mL\b|\b(?:TSH|thyroid[- ]stimulating\s+hormone)[:\s]*(\d+(?:\.\d+)?)\s*(?:mIU\/L|µIU\/mL)\b|\b(?:creatinine)[:\s]*(\d+(?:\.\d+)?)\s*mg\/dL\b|\b(?:eGFR)[:\s]*(\d{1,3})\s*mL\/min\b|\b(?:INR|PT)[:\s]*(\d+(?:\.\d+)?)\b|\b(?:CD4\s+(?:count|cells?))[:\s]*(\d{2,4})\s*(?:cells\/μL|cells\/mm3|\/μL)?\b|\b(?:viral\s+load)[:\s]*(\d+)\s*(?:copies\/mL|IU\/mL)?\b|\b(?:total\s+cholesterol|LDL|HDL)[:\s]*(\d{2,3})\s*mg\/dL\b|\b(?:troponin)[:\s]*(\d+(?:\.\d+)?)\s*(?:ng\/mL|μg\/L)\b|\b(?:platelet\s+count|platelets)[:\s]*(\d{2,3}(?:,\d{3})?)\s*(?:K\/μL|×10³\/μL)?\b/gi,
  },
  {
    name: 'Age Over 89 (HIPAA Suppressed)',
    category: 'HIPAA Temporal Identifier',
    severity: 'MEDIUM',
    requiresContext: false,
    re: /\b(?:age[:\s]*|aged\s+|is\s+)(9\d|1[01]\d)\s*(?:years?(?:\s+old)?|yr\.?s?)\b|\b(9\d|1[01]\d)[- ]year[- ]old\s+(?:patient|man|woman|male|female|person)\b/gi,
  },
  {
    name: 'Medical Event Date',
    category: 'HIPAA Temporal Identifier',
    severity: 'MEDIUM',
    requiresContext: false,
    re: /\b(?:admission|admitted|admit)\s+date[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|\b(?:discharge|discharged)\s+date[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|\b(?:date\s+of\s+death|death\s+date|DOD)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|\b(?:procedure|surgery|operation|transplant)\s+date[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b|\b(?:date\s+of\s+service|DOS|service\s+date)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b/gi,
  },
  {
    name: 'Biometric Health Identifier',
    category: 'Biometric Identifier',
    severity: 'HIGH',
    requiresContext: true,
    re: /\b(?:fingerprint\s+(?:scan|match|record|ID|used\s+for|for\s+patient)|retinal\s+(?:scan|ID|map)|iris\s+(?:scan|ID)|voiceprint\s+(?:record|ID|used|for|to\s+verify|verification)|voice\s+(?:verification|authentication)\s+(?:for\s+)?(?:patient|member)|facial\s+(?:recognition|scan|photograph)\s+(?:match|ID|on\s+file)?|patient\s+(?:face\s+photo|photograph|facial\s+photo|clinical\s+photo)|full[-\s]?face\s+(?:photo|photograph|image)|clinical\s+photograph|DNA\s+(?:profile|sample|match|sequence)\s+(?:on\s+)?file|blood\s+type[:\s]*(?:A|B|AB|O)[+-])\b/gi,
  },
  {
    name: 'Clinical Notes Context',
    category: 'Clinical Documentation',
    severity: 'HIGH',
    requiresContext: true,
    re: /\b(?:chief\s+complaint[:\s]|CC[:\s](?:\w+)){1}|\b(?:history\s+of\s+present\s+illness[:\s]|HPI[:\s])|\b(?:assessment\s+and\s+plan[:\s]|A[:\s]?(?:&|and)\s*P(?:lan)?[:\s])|\b(?:past\s+medical\s+history[:\s]|PMH[:\s]|PMHx[:\s])|\b(?:review\s+of\s+systems[:\s]|ROS[:\s])|\b(?:patient\s+(?:presents?|presented|is\s+a|reports?)\s+(?:with|to))|\b(?:subjective[:\s]|objective[:\s]|SOAP\s+note)|\b(?:discharge\s+summary|admission\s+note|progress\s+note|operative\s+report|consultation\s+note)\b/gi,
  },
  {
    name: 'Patient Name in Health Context',
    category: 'HIPAA Identity Linkage',
    severity: 'CRITICAL',
    requiresContext: false,
    re: /(?:Patient(?:\s+Name)?)\s*[:=]\s*(?:(?:Mr|Mrs|Ms|Dr)\.?\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+|(?:Pt\s+Name)\s*[:=]\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+|(?:Patient)\s+(?:DOB|SSN|MRN)\s*[:=]/g,
  },
];

// ── Rule A / B helpers ─────────────────────────────────────────────────────
const CLAIM_RE       = /\bClaim\s+(?:No|Number|#|ID)?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|\bInsurance\s+Claim\s+(?:No|Number|#)?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|\bClaim\s+#\s*([A-Z0-9][A-Z0-9-]{3,14})\b/gi;
const PRIOR_AUTH_RE  = /\bPrior\s+Auth(?:orization)?(?:\s+(?:No|Number|#|ID))?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|\bPA\s+(?:No|Number|#)[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b|\bPre[-\s]?Auth(?:orization)?(?:\s+(?:No|Number|#))?[:\s#-]*([A-Z0-9][A-Z0-9-]{3,14})\b/gi;
const PRIOR_AUTH_PHRASE_RE = /\bprior\s+auth(?:orization)?\b/gi;
const SUBSCRIBER_BARE_RE   = /\bSubscriber\s+(\d{4,12})\b/gi;
const BENEFICIARY_BARE_RE  = /\bBeneficiary\s+(\d{4,12})\b/gi;
const EMAIL_RE  = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE  = /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g;

// ── Rule C: name + health event ────────────────────────────────────────────
const NAME_HEALTH_EVENT_RE = /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:was|were|has|had|is|have|will\s+be)\s+(?:diagnosed\s+with|admitted\s+(?:for|to|with)|treated\s+for|prescribed|hospitalized|discharged|referred\s+for|tested\s+positive|positive\s+for|scheduled\s+for\s+(?:surgery|biopsy|procedure|chemo)|recovering\s+from|suffering\s+from)|\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:had|has|suffered|experienced)\s+(?:a\s+)?(?:miscarriage|stroke|heart\s+attack|seizure|overdose|surgery|biopsy|transplant|relapse|abortion|stillbirth)|\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})'?s?\s+(?:pathology\s+report|biopsy\s+(?:result|report)|lab\s+(?:result|report)|medical\s+record|MRI|CT\s+scan|X[-\s]?ray|diagnosis|prescription|health\s+record|insurance\s+claim|radiology\s+report|test\s+results?)/g;

const NON_PERSON_NAMES = new Set([
  'Blood Pressure', 'Heart Rate', 'Blood Sugar', 'Blood Type', 'Blood Count',
  'Blood Work', 'Chest Pain', 'Heart Attack', 'Type One', 'Type Two',
  'Stage One', 'Stage Two', 'Stage Three', 'Stage Four', 'United States',
  'New York', 'Los Angeles', 'Health Plan', 'Health Care', 'Health Record',
  'Medical Record', 'Patient Care', 'Vital Signs', 'Lab Result', 'Lab Report',
  'Test Result', 'North America', 'Mental Health', 'Public Health',
  'Brain Tumor', 'Lung Cancer', 'Breast Cancer', 'Skin Cancer',
]);

// ── Helpers ────────────────────────────────────────────────────────────────
function _hasPersonalContext(text, start, end) {
  const lo = Math.max(0, start - CONTEXT_WINDOW);
  const hi = Math.min(text.length, end + CONTEXT_WINDOW);
  PERSONAL_CONTEXT_RE.lastIndex = 0;
  return PERSONAL_CONTEXT_RE.test(text.slice(lo, hi));
}

function _hasHealthContext(text, start, end) {
  const lo = Math.max(0, start - CONTEXT_WINDOW);
  const hi = Math.min(text.length, end + CONTEXT_WINDOW);
  HEALTH_CONTEXT_RE.lastIndex = 0;
  return HEALTH_CONTEXT_RE.test(text.slice(lo, hi));
}

function _snippet(text, start, end) {
  const lo = Math.max(0, start - 60);
  const hi = Math.min(text.length, end + 60);
  return `...${text.slice(lo, hi).replace(/\s+/g, ' ').trim()}...`;
}

function _maskValue(value) {
  if (value.length <= 2) return '*'.repeat(value.length);
  return value.slice(0, 2) + '*'.repeat(value.length - 2);
}

function _deduplicate(findings) {
  const seen = new Set();
  return findings
    .filter(f => {
      const key = `${f.position}|${f.type}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => a.position - b.position);
}

// ── Medication detection ───────────────────────────────────────────────────
function _detectMedications(text) {
  const results = [];
  MEDICATION_CLASS_RE.lastIndex = 0;
  for (const m of text.matchAll(MEDICATION_CLASS_RE)) {
    const lo = Math.max(0, m.index - 150);
    const hi = Math.min(text.length, m.index + m[0].length + 150);
    const window = text.slice(lo, hi);
    DOSAGE_RE.lastIndex = 0;
    PRESCRIPTION_CONTEXT_RE.lastIndex = 0;
    PERSONAL_CONTEXT_RE.lastIndex = 0;
    const hasDose    = DOSAGE_RE.test(window);
    const hasRxCtx   = PRESCRIPTION_CONTEXT_RE.test(window);
    const hasPatient = PERSONAL_CONTEXT_RE.test(window);
    if ((hasDose || hasRxCtx) && hasPatient) {
      results.push({
        category:     'Prescription Medication',
        type:         'Medication with Dosage / Patient Context',
        severity:     'HIGH',
        value:        m[0],
        masked_value: '[MEDICATION]',
        position:     m.index,
        context:      _snippet(text, m.index, m.index + m[0].length),
        reason:       'HIPAA PHI: Prescription medication linked to a patient',
      });
    }
  }
  return results;
}

/**
 * @param {string} text
 * @returns {{
 *   detected: boolean,
 *   findings: Array,
 *   count: number,
 *   has_critical: boolean,
 *   has_high: boolean,
 *   categories_detected: string[],
 *   risk_level: string,
 *   masked_text: string
 * }}
 */
export function analyzePHI(text) {
  const findings = [];
  let maskedText = text;
  let offset = 0;

  const isDeidentified = DEIDENT_RE.test(text);

  // ── Step 1: Administrative PHI patterns ─────────────────────────────────
  for (const spec of ADMIN_PHI_PATTERNS) {
    spec.re.lastIndex = 0;
    for (const m of text.matchAll(spec.re)) {
      if (spec.requiresContext && !_hasPersonalContext(text, m.index, m.index + m[0].length)) continue;
      const value = m.slice(1).find(g => g !== undefined) ?? m[0];
      const masked = _maskValue(value);
      const maskedFull = m[0].replace(value, masked);

      findings.push({
        category:     spec.category,
        type:         spec.name,
        severity:     spec.severity,
        value:        m[0],
        masked_value: maskedFull,
        position:     m.index,
        context:      _snippet(text, m.index, m.index + m[0].length),
        reason:       `HIPAA PHI: ${spec.name} detected`,
      });

      // Apply mask to maskedText
      const adjStart = m.index + offset;
      const adjEnd   = m.index + m[0].length + offset;
      const tag = `[${spec.name.toUpperCase()}]`;
      maskedText = maskedText.slice(0, adjStart) + tag + maskedText.slice(adjEnd);
      offset += tag.length - m[0].length;
    }
  }

  // ── Step 2: Standalone ICD-10 codes with nearby label ───────────────────
  const foundCodes = new Set(
    findings.filter(f => f.type.includes('ICD')).map(f => {
      ICD10_CODE_RE.lastIndex = 0;
      const m2 = ICD10_CODE_RE.exec(f.value);
      return m2 ? m2[1].toUpperCase() : null;
    }).filter(Boolean)
  );

  ICD10_CODE_RE.lastIndex = 0;
  for (const m of text.matchAll(ICD10_CODE_RE)) {
    const code = m[1].toUpperCase();
    if (foundCodes.has(code)) continue;
    const lo = Math.max(0, m.index - 200);
    const hi = Math.min(text.length, m.index + m[0].length + 50);
    ICD10_LABEL_RE.lastIndex = 0;
    if (ICD10_LABEL_RE.test(text.slice(lo, hi))) {
      foundCodes.add(code);
      findings.push({
        category:     'Clinical Code',
        type:         'ICD-10 Diagnosis Code (standalone)',
        severity:     'HIGH',
        value:        m[1],
        masked_value: '[ICD-CODE]',
        position:     m.index,
        context:      _snippet(text, m.index, m.index + m[0].length),
        reason:       'HIPAA PHI: ICD-10 diagnosis code',
      });
    }
  }

  // ── Step 3: Condition / diagnosis plaintext ──────────────────────────────
  if (!isDeidentified) {
    for (const spec of CONDITION_PATTERNS) {
      spec.re.lastIndex = 0;
      for (const m of text.matchAll(spec.re)) {
        if (spec.severity === 'HIGH') {
          if (!_hasPersonalContext(text, m.index, m.index + m[0].length)) continue;
        }
        findings.push({
          category:     'Health Condition Disclosure',
          type:         spec.category,
          severity:     spec.severity,
          value:        m[0],
          masked_value: `[${spec.category.toUpperCase().replace(/ /g, '_')}]`,
          position:     m.index,
          context:      _snippet(text, m.index, m.index + m[0].length),
          reason:       `HIPAA PHI: Sensitive health condition (${spec.category})`,
        });
      }
    }
  }

  // ── Step 4: Medication + dosage ──────────────────────────────────────────
  findings.push(..._detectMedications(text));

  // ── Step 5: Rule A (claims, prior auth) + Rule B (email/phone in health ctx) ──
  CLAIM_RE.lastIndex = 0;
  for (const m of text.matchAll(CLAIM_RE)) {
    if (_hasHealthContext(text, m.index, m.index + m[0].length)) {
      findings.push({
        category:     'Health Insurance Identifier',
        type:         'Health Insurance Claim Number',
        severity:     'HIGH',
        value:        m[0],
        masked_value: '[CLAIM_NUMBER]',
        position:     m.index,
        context:      _snippet(text, m.index, m.index + m[0].length),
        reason:       'HIPAA PHI: Insurance claim number linked to healthcare',
      });
    }
  }

  PRIOR_AUTH_RE.lastIndex = 0;
  for (const m of text.matchAll(PRIOR_AUTH_RE)) {
    findings.push({
      category:     'Health Insurance Identifier',
      type:         'Prior Authorization Number',
      severity:     'HIGH',
      value:        m[0],
      masked_value: '[PRIOR_AUTH_NUMBER]',
      position:     m.index,
      context:      _snippet(text, m.index, m.index + m[0].length),
      reason:       'HIPAA PHI: Prior authorization number',
    });
  }

  PRIOR_AUTH_PHRASE_RE.lastIndex = 0;
  for (const m of text.matchAll(PRIOR_AUTH_PHRASE_RE)) {
    if (_hasPersonalContext(text, m.index, m.index + m[0].length)) {
      if (!findings.some(f => f.position === m.index)) {
        findings.push({
          category:     'Health Insurance Identifier',
          type:         'Prior Authorization (Health Context)',
          severity:     'MEDIUM',
          value:        m[0],
          masked_value: '[PRIOR_AUTH]',
          position:     m.index,
          context:      _snippet(text, m.index, m.index + m[0].length),
          reason:       'HIPAA PHI: Prior authorization linked to a patient',
        });
      }
    }
  }

  SUBSCRIBER_BARE_RE.lastIndex = 0;
  for (const m of text.matchAll(SUBSCRIBER_BARE_RE)) {
    if (_hasHealthContext(text, m.index, m.index + m[0].length)) {
      findings.push({
        category: 'Health Insurance Identifier', type: 'Health Plan Subscriber Number',
        severity: 'HIGH', value: m[0], masked_value: '[SUBSCRIBER_NUMBER]',
        position: m.index, context: _snippet(text, m.index, m.index + m[0].length),
        reason: 'HIPAA PHI: Subscriber number in healthcare context',
      });
    }
  }

  BENEFICIARY_BARE_RE.lastIndex = 0;
  for (const m of text.matchAll(BENEFICIARY_BARE_RE)) {
    if (_hasHealthContext(text, m.index, m.index + m[0].length)) {
      findings.push({
        category: 'Health Insurance Identifier', type: 'Health Plan Beneficiary Number (bare)',
        severity: 'HIGH', value: m[0], masked_value: '[BENEFICIARY_NUMBER]',
        position: m.index, context: _snippet(text, m.index, m.index + m[0].length),
        reason: 'HIPAA PHI: Beneficiary number in healthcare context',
      });
    }
  }

  EMAIL_RE.lastIndex = 0;
  for (const m of text.matchAll(EMAIL_RE)) {
    if (_hasHealthContext(text, m.index, m.index + m[0].length)) {
      findings.push({
        category: 'Health-Linked Generic Identifier', type: 'Email Address in Healthcare Context',
        severity: 'HIGH', value: m[0], masked_value: '[EMAIL_IN_HEALTH_CONTEXT]',
        position: m.index, context: _snippet(text, m.index, m.index + m[0].length),
        reason: 'HIPAA PHI Rule B: Email linked to healthcare context',
      });
    }
  }

  PHONE_RE.lastIndex = 0;
  for (const m of text.matchAll(PHONE_RE)) {
    if (_hasHealthContext(text, m.index, m.index + m[0].length)) {
      findings.push({
        category: 'Health-Linked Generic Identifier', type: 'Phone Number in Healthcare Context',
        severity: 'HIGH', value: m[0], masked_value: '[PHONE_IN_HEALTH_CONTEXT]',
        position: m.index, context: _snippet(text, m.index, m.index + m[0].length),
        reason: 'HIPAA PHI Rule B: Phone linked to healthcare context',
      });
    }
  }

  // ── Step 6: Rule C — proper name + health event ──────────────────────────
  NAME_HEALTH_EVENT_RE.lastIndex = 0;
  for (const m of text.matchAll(NAME_HEALTH_EVENT_RE)) {
    const name = m.slice(1).find(g => g !== undefined);
    if (name && !NON_PERSON_NAMES.has(name)) {
      findings.push({
        category:     'Health-Linked Identity',
        type:         'Person Name with Health Event',
        severity:     'HIGH',
        value:        name,
        masked_value: '[PERSON_NAME_HEALTH_EVENT]',
        position:     m.index,
        context:      _snippet(text, m.index, m.index + m[0].length),
        reason:       'HIPAA PHI Rule C: Person identified by name linked to a health event',
      });
    }
  }

  // ── Step 7: Deduplicate and sort ─────────────────────────────────────────
  const unique = _deduplicate(findings);

  const has_critical = unique.some(f => f.severity === 'CRITICAL');
  const has_high     = unique.some(f => f.severity === 'HIGH');
  const categories_detected = [...new Set(unique.map(f => f.category))];

  const risk_level = unique.length === 0 ? 'SAFE'
    : has_critical ? 'CRITICAL'
    : has_high     ? 'HIGH'
    : unique.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
    : 'LOW';

  return {
    detected:            unique.length > 0,
    findings:            unique,
    count:               unique.length,
    has_critical,
    has_high,
    categories_detected,
    risk_level,
    masked_text:         maskedText,
  };
}
