const FORTUNE_500_GLOBAL = [
  // 1. Retail & Consumer
  { lei: '549300V6E985YV001234', name: 'WALMART INC.', sector: 'Retail & Consumer', country: 'United States', city: 'Bentonville', lat: 36.3729, lon: -94.2088, domain: 'walmart.com', emp: 2100000, rev: 648100, nis2: 'DORA / SEC · Critical Retail Infra', cik: '0000104169' },
  { lei: '549300TARGET00001234', name: 'TARGET CORPORATION', sector: 'Retail & Consumer', country: 'United States', city: 'Minneapolis', lat: 44.9778, lon: -93.2650, domain: 'target.com', emp: 415000, rev: 107400, nis2: 'SEC Cyber Rules · Reporting Entity', cik: '0000027419' },
  { lei: '549300PG000000001234', name: 'THE PROCTER & GAMBLE COMPANY', sector: 'Retail & Consumer', country: 'United States', city: 'Cincinnati', lat: 39.1031, lon: -84.5120, domain: 'pg.com', emp: 107000, rev: 84000, nis2: 'SEC Cyber Rules · Reporting Entity', cik: '0000080424' },

  // 2. Technology & SaaS
  { lei: '549300AMAZON00012345', name: 'AMAZON.COM, INC.', sector: 'Technology & SaaS', country: 'United States', city: 'Seattle', lat: 47.6062, lon: -122.3321, domain: 'amazon.com', emp: 1525000, rev: 574800, nis2: 'DORA · Critical ICT Provider (AWS)', cik: '0001018724' },
  { lei: 'HWKC28B2KYW2M314EF82', name: 'APPLE INC.', sector: 'Technology & SaaS', country: 'United States', city: 'Cupertino', lat: 37.3230, lon: -122.0322, domain: 'apple.com', emp: 161000, rev: 383300, nis2: 'SEC Cyber Rules · Reporting Entity', cik: '0000320193' },
  { lei: '549300GOOGLE00012345', name: 'ALPHABET INC. (GOOGLE)', sector: 'Technology & SaaS', country: 'United States', city: 'Mountain View', lat: 37.4220, lon: -122.0841, domain: 'google.com', emp: 182000, rev: 307400, nis2: 'DORA · Critical Cloud Provider (GCP)', cik: '0001652044' },
  { lei: '724500MICROSOFT00123', name: 'MICROSOFT CORPORATION', sector: 'Technology & SaaS', country: 'United States', city: 'Redmond', lat: 47.6740, lon: -122.1215, domain: 'microsoft.com', emp: 221000, rev: 211900, nis2: 'DORA · Critical Cloud Provider (Azure)', cik: '0000789019' },
  { lei: '549300META0000000123', name: 'META PLATFORMS, INC.', sector: 'Technology & SaaS', country: 'United States', city: 'Menlo Park', lat: 37.4530, lon: -122.1817, domain: 'meta.com', emp: 67300, rev: 134900, nis2: 'SEC Cyber Rules · Reporting Entity', cik: '0001326801' },
  { lei: '5493001X70O3Z8P58405', name: 'SIEMENS AG', sector: 'Technology & SaaS', country: 'Germany', city: 'Munich', lat: 48.1351, lon: 11.5820, domain: 'siemens.com', emp: 320000, rev: 77800, nis2: 'DORA / NIS2 · Critical Industrial Tech', hrb: 'HRB 6684' },
  { lei: '969500049P7T3T7V8901', name: 'SCHNEIDER ELECTRIC SE', sector: 'Technology & SaaS', country: 'France', city: 'Rueil-Malmaison', lat: 48.8776, lon: 2.1804, domain: 'se.com', emp: 150000, rev: 36000, nis2: 'DORA / NIS2 · Critical Automation' },

  // 3. Healthcare & Life Sciences
  { lei: '549300UNITEDHEALTH12', name: 'UNITEDHEALTH GROUP INCORPORATED', sector: 'Healthcare & Life Sci', country: 'United States', city: 'Minnetonka', lat: 44.9212, lon: -93.4687, domain: 'unitedhealthgroup.com', emp: 440000, rev: 371600, nis2: 'SEC Cyber Rules · Critical Healthcare', cik: '0000731766' },
  { lei: '549300CVSHEALTH00123', name: 'CVS HEALTH CORPORATION', sector: 'Healthcare & Life Sci', country: 'United States', city: 'Woonsocket', lat: 42.0029, lon: -71.5148, domain: 'cvshealth.com', emp: 300000, rev: 357800, nis2: 'SEC Cyber Rules · Critical Pharmacy', cik: '0000064803' },
  { lei: '549300PFIZER00000123', name: 'PFIZER INC.', sector: 'Healthcare & Life Sci', country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060, domain: 'pfizer.com', emp: 83000, rev: 58500, nis2: 'Critical Life Sciences Entity', cik: '0000078003' },
  { lei: '549300JNJ00000001234', name: 'JOHNSON & JOHNSON', sector: 'Healthcare & Life Sci', country: 'United States', city: 'New Brunswick', lat: 40.4862, lon: -74.4518, domain: 'jnj.com', emp: 131900, rev: 85100, nis2: 'Critical Life Sciences Entity', cik: '0000200406' },
  { lei: '2138006E8FLKLO032890', name: 'ASTRAZENECA PLC', sector: 'Healthcare & Life Sci', country: 'United Kingdom', city: 'Cambridge', lat: 52.2053, lon: 0.1218, domain: 'astrazeneca.com', emp: 89000, rev: 45800, nis2: 'DORA / NIS2 · Critical Healthcare Entity', crn: '02723534' },
  { lei: '549300NOVARTIS001234', name: 'NOVARTIS AG', sector: 'Healthcare & Life Sci', country: 'Switzerland', city: 'Basel', lat: 47.5596, lon: 7.5886, domain: 'novartis.com', emp: 76000, rev: 45400, nis2: 'Critical Life Sciences Entity' },

  // 4. Banking & Capital Markets
  { lei: '8I5DZWPGB8WAJWVPR533', name: 'JPMORGAN CHASE & CO.', sector: 'Banking & Capital Mkts', country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060, domain: 'jpmorganchase.com', emp: 309900, rev: 158100, nis2: 'DORA · Systemic Financial Institution', cik: '0000019617' },
  { lei: '9DA02M1Y584NB0Z86665', name: 'BANK OF AMERICA CORPORATION', sector: 'Banking & Capital Mkts', country: 'United States', city: 'Charlotte', lat: 35.2271, lon: -80.8431, domain: 'bankofamerica.com', emp: 213000, rev: 98600, nis2: 'DORA · Systemic Financial Institution', cik: '0000070858' },
  { lei: '6FBUKFLY85TVY6GEA678', name: 'CITIGROUP INC.', sector: 'Banking & Capital Mkts', country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060, domain: 'citigroup.com', emp: 239000, rev: 78500, nis2: 'DORA · Systemic Financial Institution', cik: '0000831001' },
  { lei: '2138005T1QT6CSB94764', name: 'HSBC HOLDINGS PLC', sector: 'Banking & Capital Mkts', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'hsbc.com', emp: 220000, rev: 66100, nis2: 'DORA · Systemic Financial Institution', crn: '00617987' },
  { lei: '7LTWFZYICNSX8D621K86', name: 'DEUTSCHE BANK AG', sector: 'Banking & Capital Mkts', country: 'Germany', city: 'Frankfurt', lat: 50.1109, lon: 8.6821, domain: 'db.com', emp: 90000, rev: 28900, nis2: 'DORA · Systemic Financial Institution', hrb: 'HRB 30000' },

  // 5. Oil, Gas & Chemicals
  { lei: '549300EXXON000001234', name: 'EXXON MOBIL CORPORATION', sector: 'Oil, Gas & Chemicals', country: 'United States', city: 'Spring', lat: 30.0799, lon: -95.4172, domain: 'exxonmobil.com', emp: 62000, rev: 344500, nis2: 'NIS2 / SEC · Critical Energy Infra', cik: '0000034088' },
  { lei: '549300CHEVRON0001234', name: 'CHEVRON CORPORATION', sector: 'Oil, Gas & Chemicals', country: 'United States', city: 'San Ramon', lat: 37.7799, lon: -121.9780, domain: 'chevron.com', emp: 45600, rev: 200900, nis2: 'NIS2 / SEC · Critical Energy Infra', cik: '0000093410' },
  { lei: '2138002V8TFAVUJM6209', name: 'SHELL PLC', sector: 'Oil, Gas & Chemicals', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'shell.com', emp: 90000, rev: 380000, nis2: 'NIS2 · Essential Entity', crn: '04362580' },
  { lei: '5493005CCWD5L31Q2F83', name: 'BP P.L.C.', sector: 'Oil, Gas & Chemicals', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'bp.com', emp: 67000, rev: 240000, nis2: 'NIS2 · Essential Entity', crn: '00102498' },
  { lei: '5493007W35X172909476', name: 'TOTALENERGIES SE', sector: 'Oil, Gas & Chemicals', country: 'France', city: 'Courbevoie', lat: 48.8967, lon: 2.2531, domain: 'totalenergies.com', emp: 100000, rev: 218000, nis2: 'NIS2 · Essential Entity' },
  { lei: '724500EQUINOR0012345', name: 'EQUINOR ASA', sector: 'Oil, Gas & Chemicals', country: 'Norway', city: 'Stavanger', lat: 58.9700, lon: 5.7331, domain: 'equinor.com', emp: 22000, rev: 106000, nis2: 'NIS2 · Essential Entity' },

  // 6. Energy & Utilities
  { lei: '2138005T1QT6CSB94763', name: 'NATIONAL GRID PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'nationalgrid.com', emp: 30000, rev: 18500, nis2: 'NIS2 · Essential Entity', crn: '02367004' },
  { lei: '549300175344MC3T7083', name: 'SSE PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'Perth', lat: 56.3950, lon: -3.4308, domain: 'sse.com', emp: 12000, rev: 12400, nis2: 'NIS2 · Essential Entity', crn: 'SC117119' },
  { lei: '549300EPF2D73T7X4317', name: 'CENTRICA PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'Windsor', lat: 51.4839, lon: -0.6044, domain: 'centrica.com', emp: 21000, rev: 26500, nis2: 'NIS2 · Essential Entity', crn: '03033654' },
  { lei: 'QGW65FF55CQ672VJKSBF', name: 'E.ON SE', sector: 'Energy & Utilities', country: 'Germany', city: 'Essen', lat: 51.4556, lon: 7.0116, domain: 'eon.com', emp: 72000, rev: 93700, nis2: 'NIS2 · Essential Entity', hrb: 'HRB 26879' },
  { lei: '52990022NEP1293S0084', name: 'RWE AG', sector: 'Energy & Utilities', country: 'Germany', city: 'Essen', lat: 51.4500, lon: 7.0100, domain: 'rwe.com', emp: 20000, rev: 28600, nis2: 'NIS2 · Essential Entity', hrb: 'HRB 14525' },
  { lei: '724500L2OQVG1H544W59', name: 'TENNET HOLDING B.V.', sector: 'Energy & Utilities', country: 'Netherlands', city: 'Arnhem', lat: 51.9851, lon: 5.8987, domain: 'tennet.eu', emp: 7400, rev: 9800, nis2: 'NIS2 · Essential Entity', kvk: '09155985' },
  { lei: '558800175344MC3T7083', name: 'EDF - ELECTRICITE DE FRANCE', sector: 'Energy & Utilities', country: 'France', city: 'Paris', lat: 48.8566, lon: 2.3522, domain: 'edf.fr', emp: 170000, rev: 140000, nis2: 'NIS2 · Essential Entity' },

  // 7. Automotive & Mobility
  { lei: '549300GM000000001234', name: 'GENERAL MOTORS COMPANY', sector: 'Automotive & Mobility', country: 'United States', city: 'Detroit', lat: 42.3314, lon: -83.0458, domain: 'gm.com', emp: 163000, rev: 171800, nis2: 'SEC Cyber Rules · Automotive Infra', cik: '0001467858' },
  { lei: '549300FORD0000001234', name: 'FORD MOTOR COMPANY', sector: 'Automotive & Mobility', country: 'United States', city: 'Dearborn', lat: 42.3223, lon: -83.1763, domain: 'ford.com', emp: 177000, rev: 176200, nis2: 'SEC Cyber Rules · Automotive Infra', cik: '0000037996' },
  { lei: '549300TESLA000001234', name: 'TESLA, INC.', sector: 'Automotive & Mobility', country: 'United States', city: 'Austin', lat: 30.2672, lon: -97.7431, domain: 'tesla.com', emp: 140400, rev: 96700, nis2: 'SEC Cyber Rules · Automotive Infra', cik: '0001318605' },

  // 8. Aerospace & Defence
  { lei: '549300BOEING00001234', name: 'THE BOEING COMPANY', sector: 'Aerospace & Defence', country: 'United States', city: 'Arlington', lat: 38.8799, lon: -77.1068, domain: 'boeing.com', emp: 171000, rev: 77700, nis2: 'SEC Cyber Rules · Critical Defense Infra', cik: '0000012927' },
  { lei: '549300LOCKHEED001234', name: 'LOCKHEED MARTIN CORPORATION', sector: 'Aerospace & Defence', country: 'United States', city: 'Bethesda', lat: 38.9847, lon: -77.0947, domain: 'lockheedmartin.com', emp: 122000, rev: 67500, nis2: 'Critical Defense Supplier', cik: '0000936468' },

  // 9. Industrial & Infrastructure
  { lei: '549300GE000000001234', name: 'GENERAL ELECTRIC COMPANY', sector: 'Industrial & Infra', country: 'United States', city: 'Boston', lat: 42.3601, lon: -71.0589, domain: 'ge.com', emp: 125000, rev: 67900, nis2: 'SEC Cyber Rules · Critical Industrial', cik: '0000040545' },
  { lei: '549300CATERPILLAR123', name: 'CATERPILLAR INC.', sector: 'Industrial & Infra', country: 'United States', city: 'Irving', lat: 32.8140, lon: -96.9489, domain: 'caterpillar.com', emp: 113200, rev: 67000, nis2: 'SEC Cyber Rules · Critical Industrial', cik: '0000018255' },

  // 10. Telecommunications
  { lei: '549300ATT00000001234', name: 'AT&T INC.', sector: 'Telco & Media', country: 'United States', city: 'Dallas', lat: 32.7767, lon: -96.7970, domain: 'att.com', emp: 149900, rev: 122400, nis2: 'SEC Cyber Rules · Critical Telco Infra', cik: '0000732717' },
  { lei: '549300VERIZON0000123', name: 'VERIZON COMMUNICATIONS INC.', sector: 'Telco & Media', country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060, domain: 'verizon.com', emp: 105400, rev: 134000, nis2: 'SEC Cyber Rules · Critical Telco Infra', cik: '0001073612' },

  // 11. Insurance & Finance
  { lei: '549300BERKSHIRE00123', name: 'BERKSHIRE HATHAWAY INC.', sector: 'Insurance & Finance', country: 'United States', city: 'Omaha', lat: 41.2565, lon: -95.9345, domain: 'berkshirehathaway.com', emp: 396500, rev: 364400, nis2: 'SEC Cyber Rules · Systemic Insurance', cik: '0001067983' },

  // 12. Logistics & Transport
  { lei: '549300UPS00000001234', name: 'UNITED PARCEL SERVICE, INC. (UPS)', sector: 'Logistics & Transport', country: 'United States', city: 'Atlanta', lat: 33.7490, lon: -84.3880, domain: 'ups.com', emp: 500000, rev: 91000, nis2: 'SEC Cyber Rules · Critical Logistics', cik: '0001090727' }
];

module.exports = FORTUNE_500_GLOBAL;
