/**
 * SCAMSHIELD AI — MULTILINGUAL SCAM & PHISHING DETECTION ENGINE
 * Hackathon Edition: English, Tamil (தமிழ்), Tanglish
 * Pure Vanilla JavaScript (Client-side Heuristic Rules Engine)
 * Offline Capable • Zero External Dependencies • Privacy Focused
 */

'use strict';

/* ==========================================================================
   1. RULE ENGINE KNOWLEDGE BASE & DICTIONARIES
   ========================================================================== */

const ThreatRules = {
  // 1. OTP Credential Theft
  otp: {
    category: "OTP Scam",
    weight: 35,
    title: "OTP Credential Solicitation",
    patterns: [
      /\b(?:enter|share|give|send|provide|tell|verify)\s+(?:your\s+)?otp\b/i,
      /\b(?:one[\s-]time[\s-]password|verification\s+code|security\s+code|sms\s+code)\b/i,
      /\botp\s+(?:immediately|now|urgent|required|needed)\b/i,
      /\b(?:share|enter)\s+otp\b/i,
      // Tamil
      /ஓடிபி/u,
      /ஒருமுறை\s*கடவுச்சொல்/u,
      /otp\s*கொடுக்கவும்/ui,
      /otp\s*பகிரவும்/ui,
      /otp\s*அனுப்பவும்/ui,
      /கடவு\s*எண்/u,
      // Tanglish
      /\botp\s+(?:enter\s+pannu|kudu|kudunga|share\s+pannu|anupu|sollu|podunga|podavum)\b/i,
      /\botp\s+varum\b/i
    ],
    explanation: "Fraudsters request One-Time Passwords (OTP) to finalize unauthorized bank transfers, initiate SIM swaps, or take over digital wallets.",
    advice: "Never share an OTP with anyone. Bank employees, customer support, and law enforcement will NEVER ask for your OTP."
  },

  // 2. Account Blocking & Banking Threats
  accountThreat: {
    category: "Banking Scam",
    weight: 30,
    title: "Urgent Account Blocking Threat",
    patterns: [
      /\b(?:bank\s+account|debit\s+card|credit\s+card|sim\s+card|netbanking)\s+(?:will\s+be\s+)?(?:blocked|suspended|frozen|deactivated|closed|terminated)\b/i,
      /\baccount\s+(?:will\s+be\s+)?blocked\b/i,
      /\b(?:kyc|pan\s+card|aadhaar)\s+(?:expired|pending|update\s+required|suspended|deactivated)\b/i,
      /\bupdate\s+your\s+(?:pan|aadhaar|kyc)\b/i,
      /\blink\s+aadhaar\s+to\s+(?:pan|bank|sim)\b/i,
      // Tamil
      /வங்கி\s*கணக்கு\s*இன்று\s*முடக்கப்படும்/u,
      /கணக்கு\s*முடக்கப்படும்/u,
      /கணக்கு\s*நிறுத்தப்படும்/u,
      /கேஒய்சி\s*(?:புதுப்பிக்க|முடியும்)/u,
      /பான்\s*கார்டு\s*காலாவதி/u,
      // Tanglish
      /\baccount\s+(?:block\s+aagapoguthu|block\s+aagum|mudakkapadum|close\s+aagum)\b/i,
      /\bkyc\s+(?:update\s+pannunga|pending\s+irukku)\b/i,
      /\bpan\s+card\s+link\s+pannu\b/i
    ],
    explanation: "Scammers create artificial panic claiming your bank account or debit card will be immediately suspended to force irrational compliance.",
    advice: "Legitimate financial institutions never freeze accounts abruptly via SMS or WhatsApp links. Contact your branch directly through official numbers."
  },

  // 3. Pressure Tactics & Immediate Action
  urgency: {
    category: "Coercive Urgency",
    weight: 18,
    title: "High-Pressure Psychological Urgency",
    patterns: [
      /\b(?:immediately|right\s+now|within\s+24\s+hours|today\s+itself|today\s+only|before\s+midnight|last\s+warning|urgent\s+action\s+required)\b/i,
      /\baction\s+required\s+immediately\b/i,
      /\bdon'?t\s+delay\b/i,
      // Tamil
      /உடனே/u,
      /இன்றே/u,
      /24\s*மணி\s*நேரத்தில்/u,
      /கடைசி\s*வாய்ப்பு/u,
      /தாமதிக்க\s*வேண்டாம்/u,
      // Tanglish
      /\b(?:udane|seekiram|inikiye|inraikke|last\s+chance|ippove|neram\s+illa)\b/i
    ],
    explanation: "Pressure tactics prevent targets from pausing to think, verify details, or consult knowledgeable family members.",
    advice: "Take a deep breath. Genuine urgent administrative actions always come through verified registered mail or in-person bank notifications."
  },

  // 4. Deceptive Action Links & Downloads
  suspiciousLink: {
    category: "Phishing Link",
    weight: 22,
    title: "Suspicious Action Link or APK Request",
    patterns: [
      /\b(?:click\s+(?:this\s+)?link|click\s+here|tap\s+link|open\s+link|visit\s+link)\b/i,
      /\bdownload\s+(?:apk|app|file|attachment)\b/i,
      /\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9_-]+/i,
      /\bhttps?:\/\/[^\s]+/i,
      // Tamil
      /லிங்கை\s*கிளிக்\s*(?:செய்யவும்|செய்து)/u,
      /இங்கே\s*கிளிக்/u,
      /செயலியை\s*பதிவிறக்கம்/u,
      // Tanglish
      /\b(?:link\s+click\s+panni|link\s+click\s+pannunga|link\s+open\s+pannu|apk\s+download\s+pannu)\b/i
    ],
    explanation: "Hyperlinks in unsolicited messages typically lead to credential-harvesting phishing portals or malware (APKs) that intercept SMS OTPs.",
    advice: "Do not tap on unverified links. Never install APK files sent over WhatsApp, Telegram, or SMS."
  },

  // 5. UPI PIN & QR Code Traps
  upiFraud: {
    category: "UPI or Payment Scam",
    weight: 35,
    title: "UPI PIN / QR Code Receipt Trap",
    patterns: [
      /\b(?:scan\s+qr|enter\s+upi\s+pin)\s+to\s+receive\b/i,
      /\b(?:gpay|googlepay|phonepe|paytm)\s+(?:cashback|reward|refund|credited)\b/i,
      /\benter\s+(?:your\s+)?upi\s+pin\b/i,
      /\breceive\s+(?:rs\.?|inr|cash)\s+by\s+entering\s+pin\b/i,
      /\bscratch\s+card\s+won\b/i,
      // Tamil
      /யுபிஐ\s*பின்/u,
      /பணம்\s*பெற\s*qr/u,
      /பணம்\s*பெற\s*பின்னை\s*உள்ளிடவும்/u,
      /கூகிள்பே\s*பரிசு/u,
      // Tanglish
      /\b(?:upi\s+pin\s+pottu|upi\s+pin\s+podunga|qr\s+scan\s+panni\s+panam\s+vaangunga|gpay\s+cashback|phonepe\s+reward)\b/i
    ],
    explanation: "Entering your UPI PIN ALWAYS transfers money OUT of your bank account. You NEVER need to enter a UPI PIN or scan a QR code to receive money.",
    advice: "If anyone claims you must enter a UPI PIN or scan a QR code to receive funds, it is an absolute scam. Cancel the transaction immediately."
  },

  // 6. Fake Work-From-Home / Part-Time Jobs
  jobScam: {
    category: "Fake Job Scam",
    weight: 30,
    title: "Deceptive Job Offer & Upfront Fee Trap",
    patterns: [
      /\b(?:work\s+from\s+home|part[\s-]time\s+job)\s+earn\s+(?:rs\.?|\$)\s*[0-9]+/i,
      /\bearn\s+[0-9]+k?\s+(?:daily|per\s+day)\b/i,
      /\b(?:like\s+youtube\s+videos|rate\s+google\s+hotels|telegram\s+task)\b/i,
      /\b(?:pay\s+registration\s+fee|refundable\s+deposit|joining\s+fee)\b/i,
      // Tamil
      /வீட்டில்\s*இருந்தே\s*வேலை/u,
      /பகுதி\s*நேர\s*வேலை/u,
      /தினசரி\s*வருமானம்/u,
      /பதிவு\s*கட்டணம்/u,
      // Tanglish
      /\b(?:veetla\s+irundhe\s+velai|part\s+time\s+job|dhinasari\s+panam|registration\s+fee\s+kattanum)\b/i
    ],
    explanation: "Cybercrime syndicates advertise easy daily earnings for simple online tasks, but require initial 'security deposits' that you never recover.",
    advice: "Reputable companies NEVER demand payment, training fees, or deposits for hiring employees."
  },

  // 7. Lottery, KBC & Prize Giveaways
  lotteryScam: {
    category: "Lottery or Prize Scam",
    weight: 32,
    title: "Unsolicited Lottery / Prize Winner Scam",
    patterns: [
      /\bcongratulations!?\s+you\s+(?:have\s+)?won\b/i,
      /\b(?:kbc\s+lottery|lucky\s+draw\s+winner|won\s+25\s+lakhs?|cash\s+prize\s+winner|won\s+a\s+car)\b/i,
      /\bclaim\s+your\s+(?:free\s+)?(?:prize|lottery|reward)\b/i,
      // Tamil
      /பரிசு\s*வென்றுள்ளீர்கள்/u,
      /லாட்டரி\s*வென்றது/u,
      /குலுக்கல்\s*பரிசு/u,
      // Tanglish
      /\b(?:congrats\s+neenga\s+win\s+pannitinga|lottery\s+prize|parisu\s+kedaichurukku|jackpot\s+adichidhu)\b/i
    ],
    explanation: "You cannot win a lottery or raffle that you never entered. Fraudsters ask for 'processing fees' or 'taxes' upfront before vanishing.",
    advice: "Ignore and delete all notifications claiming you won prizes or lotteries you did not participate in."
  },

  // 8. Delivery, Courier & Customs Impersonation
  deliveryScam: {
    category: "Delivery Scam",
    weight: 25,
    title: "Fake Postal Parcel / Courier Impersonation",
    patterns: [
      /\b(?:india\s+post|speed\s+post|dhl|fedex|blue\s+dart)\s+(?:package|parcel|shipment)\b/i,
      /\b(?:failed\s+delivery|address\s+incomplete|package\s+suspended|delivery\s+pending)\b/i,
      /\b(?:pay\s+re-?delivery\s+fee|customs\s+clearance\s+fee)\b/i,
      // Tamil
      /பார்சல்\s*நிலுவையில்\s*உள்ளது/u,
      /தபால்\s*நிலையம்/u,
      /டெலிவரி\s*கட்டணம்/u,
      // Tanglish
      /\b(?:parcel\s+vandhurukku|delivery\s+address\s+thappa\s+irukku|courier\s+fee\s+kattunga)\b/i
    ],
    explanation: "Criminals pose as postal services claiming your parcel is held due to incomplete address details, prompting you to enter credit card info on a phishing site.",
    advice: "Check the official tracking website directly using your genuine tracking ID. Do not click links inside unsolicited parcel SMS."
  },

  // 9. High-Return Investment & Crypto Scams
  investmentScam: {
    category: "Investment Scam",
    weight: 30,
    title: "Guaranteed High Return / Crypto Fraud",
    patterns: [
      /\b(?:guaranteed|risk[\s-]free)\s+(?:returns?|profits?|100%\s+profit)\b/i,
      /\bdouble\s+your\s+(?:money|investment)\s+in\s+[0-9]+\s+(?:days|hours)\b/i,
      /\b(?:crypto\s+trading\s+signals|forex\s+guaranteed|passive\s+income\s+bot)\b/i,
      // Tamil
      /முதலீடு\s*செய்யுங்கள்/u,
      /இரட்டிப்பு\s*பணம்/u,
      /உத்தரவாத\s*லாபம்/u,
      // Tanglish
      /\b(?:investment\s+double\s+aagum|guaranteed\s+return|panam\s+double\s+aagum)\b/i
    ],
    explanation: "Promises of unrealistic, guaranteed profits in short periods are hallmark indicators of Ponzi schemes and unauthorized investment operations.",
    advice: "Legitimate investments always carry risk and are registered with regulatory bodies like SEBI or RBI. Avoid social media investment tips."
  },

  // 10. Law Enforcement / Government Impersonation
  impersonationScam: {
    category: "Impersonation Scam",
    weight: 35,
    title: "Law Enforcement / Digital Arrest Threat",
    patterns: [
      /\b(?:cbi|police|customs|cyber\s+crime|income\s+tax)\s+(?:department|notice|warrant|investigation)\b/i,
      /\b(?:arrest\s+warrant|digital\s+arrest|illegal\s+parcel\s+drugs)\b/i,
      /\b(?:send\s+debit\s+card|cvv|atm\s+pin)\b/i,
      // Tamil
      /காவல்துறை\s*எச்சரிக்கை/u,
      /சிபிஐ/u,
      /கைது\s*ஆணை/u,
      /சிவிவி\s*எண்/u,
      // Tanglish
      /\b(?:police\s+case|cbi\s+investigation|court\s+summon|arrest\s+warrant)\b/i
    ],
    explanation: "Cybercriminals impersonate police, CBI, or customs officials claiming you are implicated in money laundering or narcotics, demanding extortion payments.",
    advice: "Indian law enforcement does not conduct 'digital arrests' over WhatsApp or Skype, nor do they demand money transfers to clear names."
  }
};

/* ==========================================================================
   2. CORE SCAM DETECTION ENGINE
   ========================================================================== */

const ScamShieldEngine = {
  /**
   * Detect language mode of message
   * @param {string} text 
   * @param {string} userSelection ('auto', 'en', 'ta', 'tanglish')
   * @returns {string} Detected language label
   */
  detectLanguage(text, userSelection = 'auto') {
    if (userSelection && userSelection !== 'auto') {
      if (userSelection === 'ta') return 'Tamil (தமிழ்)';
      if (userSelection === 'tanglish') return 'Tanglish';
      if (userSelection === 'en') return 'English';
    }

    // Check for Tamil Unicode range (U+0B80 to U+0BFF)
    const hasTamilScript = /[\u0B80-\u0BFF]/.test(text);
    if (hasTamilScript) return 'Tamil (தமிழ்)';

    // Check for common Tanglish markers
    const tanglishTokens = [
      /\b(?:ungal|ungala|unga|engal|namma)\b/i,
      /\b(?:panam|kaasu|roobai)\b/i,
      /\b(?:aagum|aagapoguthu|aachu|aagathu)\b/i,
      /\b(?:panni|pannunga|pannu|pannavum)\b/i,
      /\b(?:kudukavum|kudunga|kudu|kuduthu)\b/i,
      /\b(?:anupu|anupunga|sollu|sollunga)\b/i,
      /\b(?:varum|irukku|irukkanga|kattunga|kattanum)\b/i,
      /\b(?:udane|seekiram|inikiye|inraikke)\b/i,
      /\b(?:indha|andha|yedhu|endha)\b/i,
      /\b(?:kedaikum|mudiyum|mudiyathu|adichidhu)\b/i
    ];

    let tanglishHits = 0;
    for (const token of tanglishTokens) {
      if (token.test(text)) tanglishHits++;
    }

    if (tanglishHits >= 2) return 'Tanglish';
    return 'English';
  },

  /**
   * Primary Heuristic Threat Assessment
   * @param {string} message 
   * @param {string} selectedLang
   * @returns {object} Full analysis report
   */
  analyze(message, selectedLang = 'auto') {
    const trimmed = (message || '').trim();
    if (!trimmed) {
      return {
        score: 0,
        riskLevel: 'low',
        category: 'Unknown or Unclear',
        detectedLanguage: 'English',
        warningSigns: [],
        highlights: [],
        recommendations: [],
        verdictTitle: "No Message Provided",
        verdictDescription: "Please paste or type a message to begin security analysis."
      };
    }

    const detectedLanguage = this.detectLanguage(trimmed, selectedLang);
    const detectedRules = [];
    const highlightIntervals = [];
    const categoryHits = {};

    let totalWeight = 0;

    // Scan every rule vector
    for (const [ruleKey, rule] of Object.entries(ThreatRules)) {
      let matchedInRule = false;
      let matchedPhrase = null;
      let matchInterval = null;

      for (const pattern of rule.patterns) {
        const match = pattern.exec(trimmed);
        if (match) {
          matchedInRule = true;
          matchedPhrase = match[0];
          matchInterval = {
            start: match.index,
            end: match.index + match[0].length,
            phrase: match[0],
            severity: rule.weight >= 30 ? 'high' : 'med'
          };
          break; // Avoid double counting inside the same rule
        }
      }

      if (matchedInRule && matchInterval) {
        totalWeight += rule.weight;
        detectedRules.push({
          key: ruleKey,
          title: rule.title,
          category: rule.category,
          weight: rule.weight,
          severity: rule.weight >= 30 ? 'high' : 'med',
          detectedPhrase: matchedPhrase,
          explanation: rule.explanation,
          advice: rule.advice
        });

        highlightIntervals.push(matchInterval);

        // Track category frequency for classification
        categoryHits[rule.category] = (categoryHits[rule.category] || 0) + rule.weight;
      }
    }

    // Compound Synergies (Boost risk if compounding toxic vectors appear together)
    const hasOtp = detectedRules.some(r => r.key === 'otp');
    const hasAccountThreat = detectedRules.some(r => r.key === 'accountThreat');
    const hasUrgency = detectedRules.some(r => r.key === 'urgency');
    const hasLink = detectedRules.some(r => r.key === 'suspiciousLink');
    const hasUpi = detectedRules.some(r => r.key === 'upiFraud');

    let synergyBonus = 0;
    if (hasAccountThreat && hasUrgency && hasOtp) synergyBonus += 25;
    else if (hasAccountThreat && hasOtp) synergyBonus += 20;
    else if (hasAccountThreat && hasLink) synergyBonus += 15;
    else if (hasUpi && hasUrgency) synergyBonus += 15;
    else if (hasOtp && hasLink) synergyBonus += 15;

    let finalScore = Math.min(100, totalWeight + synergyBonus);

    // If completely benign message (e.g., normal conversation)
    if (detectedRules.length === 0) {
      finalScore = 0;
    }

    // Categorize Risk Level
    let riskLevel = 'low';
    if (finalScore >= 61) {
      riskLevel = 'high';
    } else if (finalScore >= 31) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    // Determine Likely Scam Category
    let likelyCategory = 'Unknown or Unclear';
    let maxWeight = 0;
    for (const [cat, w] of Object.entries(categoryHits)) {
      if (w > maxWeight) {
        maxWeight = w;
        likelyCategory = cat;
      }
    }

    if (detectedRules.length === 0) {
      likelyCategory = 'Unknown or Unclear';
    }

    // Merge Overlapping Highlights safely for DOM rendering
    const mergedHighlights = this.mergeIntervals(highlightIntervals);

    // Generate Tailored Safety Checklist
    const recommendations = this.generateSafetyChecklist(detectedRules, riskLevel);

    // Headline Descriptions
    let verdictTitle = "No Major Warning Signs Detected";
    let verdictDescription = "No major warning signs detected. This does not guarantee that the message is safe.";

    if (riskLevel === 'high') {
      verdictTitle = "CRITICAL THREAT: High Scam Probability";
      verdictDescription = "This message exhibits strong characteristics of an active cyber attack. Do not click links, share OTPs, or reply.";
    } else if (riskLevel === 'medium') {
      verdictTitle = "SUSPICIOUS: Exercise Caution";
      verdictDescription = "This message contains potential warning indicators. Verify the sender through official channels before taking action.";
    }

    return {
      score: finalScore,
      riskLevel,
      category: likelyCategory,
      detectedLanguage,
      warningSigns: detectedRules,
      highlights: mergedHighlights,
      recommendations,
      verdictTitle,
      verdictDescription,
      analyzedText: trimmed
    };
  },

  /**
   * Interval merger to prevent broken HTML tags when phrases overlap
   */
  mergeIntervals(intervals) {
    if (!intervals || intervals.length === 0) return [];

    // Sort by start index
    const sorted = [...intervals].sort((a, b) => a.start - b.start);
    const merged = [sorted[0]];

    for (let i = 1; i < sorted.length; i++) {
      const current = sorted[i];
      const previous = merged[merged.length - 1];

      if (current.start <= previous.end) {
        // Overlap: extend end and retain highest severity
        previous.end = Math.max(previous.end, current.end);
        if (current.severity === 'high') previous.severity = 'high';
      } else {
        merged.push(current);
      }
    }

    return merged;
  },

  /**
   * Build personalized actionable safety checklist
   */
  generateSafetyChecklist(detectedRules, riskLevel) {
    const list = [];
    const keys = new Set(detectedRules.map(r => r.key));

    if (keys.has('otp')) {
      list.push("Never share OTPs, PINs, or passwords with anyone under any circumstance.");
      list.push("Do not forward verification SMS messages to unverified numbers.");
    }
    if (keys.has('accountThreat')) {
      list.push("Contact your bank branch using official telephone numbers printed on your physical debit card.");
      list.push("Legitimate banks never terminate accounts over SMS or WhatsApp alerts.");
    }
    if (keys.has('suspiciousLink')) {
      list.push("Do not click links inside unprompted messages; never download or install APK files.");
      list.push("Check the full website domain carefully before entering any credential.");
    }
    if (keys.has('upiFraud')) {
      list.push("Remember: Entering your UPI PIN always deducts money; you NEVER enter a PIN to receive payments.");
      list.push("Do not scan random QR codes sent by unknown buyers on marketplaces.");
    }
    if (keys.has('jobScam')) {
      list.push("Avoid paying upfront registration fees, security deposits, or Telegram task enrollments.");
      list.push("Legitimate employers conduct formal interviews and do not charge job applicants.");
    }
    if (keys.has('impersonationScam')) {
      list.push("Indian law enforcement or customs NEVER conduct 'digital arrests' or demand money via video calls.");
      list.push("Do not disclose card CVV, ATM PINs, or confidential government documents.");
    }
    if (keys.has('lotteryScam')) {
      list.push("You cannot win a contest or lottery you never purchased a ticket for. Ignore prize claims.");
    }

    if (riskLevel === 'high') {
      list.push("Block the sender and report the message on WhatsApp / SMS spam filters.");
      list.push("If financial loss occurred, call the National Cybercrime Helpline 1930 immediately.");
    } else if (riskLevel === 'medium') {
      list.push("Verify the sender's claim through official customer care channels before responding.");
    } else {
      list.push("Stay alert: Fraud tactics evolve constantly. Verify unexpected requests.");
      list.push("Enable Two-Factor Authentication (2FA) with an authenticator app where available.");
    }

    return list;
  }
};

/* ==========================================================================
   3. URL INSPECTOR HEURISTICS ENGINE
   ========================================================================== */

const UrlScannerEngine = {
  scan(url) {
    const cleanUrl = (url || '').trim();
    if (!cleanUrl) {
      return {
        url: '',
        score: 0,
        riskLevel: 'low',
        protocol: 'Unknown',
        indicators: [],
        advice: [],
        verdictTitle: 'No URL Provided',
        verdictDesc: 'Please enter a URL to analyze.'
      };
    }

    let parsedUrl;
    let rawUrl = cleanUrl;
    if (!/^https?:\/\//i.test(rawUrl)) {
      rawUrl = 'http://' + rawUrl; // Default protocol for parsing
    }

    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      return {
        url: cleanUrl,
        score: 75,
        riskLevel: 'high',
        protocol: 'Invalid',
        indicators: [{
          title: "Malformed URL Structure",
          severity: "high",
          desc: "The URL syntax is malformed or invalid, a tactic frequently used to bypass standard browser security filters."
        }],
        advice: ["Do not visit malformed web links."],
        verdictTitle: "Potentially Malicious / Malformed URL",
        verdictDesc: "The URL is structurally invalid and poses potential security risks."
      };
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const indicators = [];
    let score = 0;

    // Check 1: HTTP vs HTTPS
    const isHttps = parsedUrl.protocol === 'https:';
    if (!isHttps) {
      score += 25;
      indicators.push({
        title: "Unencrypted Connection (HTTP)",
        severity: "med",
        desc: "Traffic is unencrypted and vulnerable to eavesdropping, credential tampering, or man-in-the-middle attacks."
      });
    }

    // Check 2: IP Address as Hostname
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIpHost) {
      score += 40;
      indicators.push({
        title: "Direct IP Address Host",
        severity: "high",
        desc: "The link points directly to an IP address rather than a registered domain name, commonly used to host temporary phishing kits."
      });
    }

    // Check 3: Known URL Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 'ow.ly', 'buff.ly', 't.co', 'cutt.ly', 'rb.gy', 'shorte.st'];
    const isShortener = shorteners.some(s => hostname === s || hostname.endsWith('.' + s));
    if (isShortener) {
      score += 30;
      indicators.push({
        title: "URL Shortening Service",
        severity: "med",
        desc: "URL shorteners conceal the true final destination server, making it impossible to verify the site before clicking."
      });
    }

    // Check 4: Suspicious / High-Abuse Top-Level Domains (TLDs)
    const suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.cf', '.gq', '.buzz', '.cc', '.work', '.click', '.club', '.support', '.live'];
    const hasSuspiciousTld = suspiciousTlds.some(tld => hostname.endsWith(tld));
    if (hasSuspiciousTld) {
      score += 35;
      indicators.push({
        title: "High-Risk Domain Extension (TLD)",
        severity: "high",
        desc: `Domain uses an extension often associated with disposable, low-cost registration used by cyber syndicates.`
      });
    }

    // Check 5: Brand Spoofing / Lookalike Patterns
    const brandKeywords = ['sbi', 'hdfc', 'icici', 'axis', 'pnb', 'bank', 'netbanking', 'paytm', 'gpay', 'phonepe', 'aadhaar', 'incometax'];
    const legitimateDomains = ['onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'pnbindia.in', 'paytm.com', 'google.com', 'phonepe.com', 'uidai.gov.in', 'incometax.gov.in'];

    const matchedBrand = brandKeywords.find(b => hostname.includes(b));
    const isLegitBrand = legitimateDomains.some(l => hostname === l || hostname.endsWith('.' + l));

    if (matchedBrand && !isLegitBrand) {
      score += 40;
      indicators.push({
        title: `Possible Brand Impersonation (${matchedBrand.toUpperCase()})`,
        severity: "high",
        desc: `The hostname contains '${matchedBrand}' but does not match the official legitimate banking portal domain.`
      });
    }

    // Check 6: Credential Symbol (@ Trick)
    if (cleanUrl.includes('@')) {
      score += 40;
      indicators.push({
        title: "Credential Redirection Trick (@ Symbol)",
        severity: "high",
        desc: "Using the '@' symbol in URLs forces browsers to ignore text preceding the '@' and navigate to the malicious host that follows."
      });
    }

    // Check 7: Excessive Subdomains / Hyphens
    const subdomainParts = hostname.split('.');
    if (subdomainParts.length > 3) {
      score += 15;
      indicators.push({
        title: "Excessive Subdomain Levels",
        severity: "med",
        desc: "Deep subdomain layering is frequently used to make malicious URLs appear legitimate (e.g., sbi.bank.secure-login.com)."
      });
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      score += 15;
      indicators.push({
        title: "Multiple Hyphens in Hostname",
        severity: "med",
        desc: "Scammers frequently stitch brand names together with hyphens to create deceptive lookalike URLs."
      });
    }

    // Check 8: Phishing Action Keywords in Path
    const pathTriggers = ['login', 'verify', 'update', 'kyc', 'otp', 'claim', 'bonus', 'free', 'apk', 'reward'];
    const matchedPathTrigger = pathTriggers.find(t => pathname.includes(t));
    if (matchedPathTrigger) {
      score += 18;
      indicators.push({
        title: `Phishing Lure Keyword in URL Path ('${matchedPathTrigger}')`,
        severity: "med",
        desc: `The path targets urgent credential actions, a common pattern in harvested phishing link campaigns.`
      });
    }

    // Score Capping & Categorization
    score = Math.min(100, score);
    let riskLevel = 'low';
    if (score >= 61) riskLevel = 'high';
    else if (score >= 31) riskLevel = 'medium';

    const advice = [];
    if (riskLevel === 'high') {
      advice.push("DO NOT VISIT this web address or enter any information.");
      advice.push("If you clicked this link previously, immediately change passwords and run an antivirus scan.");
    } else if (riskLevel === 'medium') {
      advice.push("Exercise extreme caution. Expand shortened URLs with an unshortener before proceeding.");
      advice.push("Never download unknown APK or executable files prompted by this site.");
    } else {
      advice.push("No major automated heuristics triggered. Still verify the website address bar before typing passwords.");
      advice.push("Remember: Valid HTTPS alone does NOT guarantee a website is legitimate.");
    }

    let verdictTitle = "URL Appears Low Risk";
    let verdictDesc = "No major warning heuristics triggered by this address structure.";
    if (riskLevel === 'high') {
      verdictTitle = "HIGH RISK: Potential Phishing / Malicious Link";
      verdictDesc = "Significant warning indicators detected. Strong likelihood of deceptive or credential harvesting intent.";
    } else if (riskLevel === 'medium') {
      verdictTitle = "CAUTION: Suspicious Link Characteristics";
      verdictDesc = "This address exhibits patterns commonly seen in spoofed links or hidden redirects.";
    }

    return {
      url: cleanUrl,
      score,
      riskLevel,
      protocol: isHttps ? 'HTTPS' : 'HTTP',
      indicators,
      advice,
      verdictTitle,
      verdictDesc
    };
  }
};

/* ==========================================================================
   4. AUDIT LOG & STORAGE MANAGER (localStorage)
   ========================================================================== */

const StorageManager = {
  STORAGE_KEY: 'scamshield_history_v1',

  getAll() {
    try {
      const data = localStorage.getItem(this.STORAGE_KEY);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  },

  save(record) {
    try {
      const list = this.getAll();
      // Prepend to show newest first
      list.unshift(record);
      // Keep up to 60 records for storage hygiene
      const trimmed = list.slice(0, 60);
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(trimmed));
      return true;
    } catch {
      return false;
    }
  },

  deleteRecord(id) {
    try {
      const list = this.getAll().filter(item => item.id !== id);
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(list));
      return true;
    } catch {
      return false;
    }
  },

  clearAll() {
    try {
      localStorage.removeItem(this.STORAGE_KEY);
      return true;
    } catch {
      return false;
    }
  },

  getStats() {
    const list = this.getAll();
    const stats = {
      total: list.length,
      low: 0,
      medium: 0,
      high: 0,
      categories: {},
      languages: {
        'English': 0,
        'Tamil (தமிழ்)': 0,
        'Tanglish': 0
      }
    };

    for (const item of list) {
      if (item.riskLevel === 'high') stats.high++;
      else if (item.riskLevel === 'medium') stats.medium++;
      else stats.low++;

      if (item.category) {
        stats.categories[item.category] = (stats.categories[item.category] || 0) + 1;
      }

      if (item.language && stats.languages[item.language] !== undefined) {
        stats.languages[item.language]++;
      } else if (item.language) {
        stats.languages[item.language] = (stats.languages[item.language] || 0) + 1;
      }
    }

    return stats;
  }
};

/* ==========================================================================
   5. DEMONSTRATION TELEMETRY DATA (TOGGLEABLE)
   ========================================================================== */

const DemoTelemetry = {
  stats: {
    total: 248,
    low: 82,
    medium: 64,
    high: 102,
    categories: {
      'Banking Scam': 78,
      'OTP Scam': 62,
      'UPI or Payment Scam': 45,
      'Fake Job Scam': 28,
      'Delivery Scam': 18,
      'Lottery or Prize Scam': 17
    },
    languages: {
      'English': 136,
      'Tamil (தமிழ்)': 72,
      'Tanglish': 40
    }
  }
};

/* ==========================================================================
   6. DAILY CYBERSECURITY TIPS REPOSITORY
   ========================================================================== */

const CyberSafetyTips = [
  {
    en: "Never share your OTP with anyone: Bank officials, police, and customer support will NEVER ask for your One-Time Password or UPI PIN.",
    ta: "உங்கள் OTP-ஐ யாரிடமும் பகிராதீர்கள்: வங்கி அதிகாரிகள் அல்லது வாடிக்கையாளர் சேவை மையத்தினர் ஒருபோதும் OTP அல்லது UPI பின்னை கேட்க மாட்டார்கள்."
  },
  {
    en: "UPI PIN is ONLY for paying money: You NEVER need to enter your UPI PIN or scan a QR code to receive money into your bank account.",
    ta: "பணம் அனுப்ப மட்டுமே UPI PIN தேவை: உங்கள் கணக்கிற்கு பணம் பெற UPI PIN போடவோ அல்லது QR குறியீட்டை ஸ்கேன் செய்யவோ தேவையில்லை."
  },
  {
    en: "Beware of urgent electricity disconnection alerts: Disconnection threats over WhatsApp asking you to call personal mobile numbers are always fraudulent.",
    ta: "மின்சாரம் துண்டிக்கப்படும் குறுஞ்செய்திகளை நம்பாதீர்கள்: வாட்ஸ்அப் வழியாக தனிநபர் எண்ணை அழைக்கக்கூறும் மின் கட்டண எச்சரிக்கைகள் மோசடியானவை."
  },
  {
    en: "No legitimate job asks for upfront fees: Any company asking for registration fees, telegram deposits, or training charges is running a recruitment scam.",
    ta: "முறையான வேலைக்கு முன்பணம் தேவையில்லை: பதிவு கட்டணம் அல்லது டெலிகிராம் டெபாசிட் கேட்கும் நிறுவனங்கள் அனைத்தும் போலி வேலை மோசடிகளே."
  },
  {
    en: "Inspect website domain addresses closely: Phishing sites mimic banks using lookalike URLs such as 'sbi-update-kyc.xyz' instead of 'onlinesbi.sbi'.",
    ta: "இணையதள முகவரியை உற்று கவனியுங்கள்: போலி தளங்கள் அசல் வங்கி பெயர் போல தோற்றமளிக்கும் மாறுபட்ட முகவரிகளை கொண்டிருக்கும்."
  },
  {
    en: "Call 1930 during the Golden Hour: If you lose money to cyber fraud, dial 1930 within 2 hours to freeze funds before fraudsters cash out.",
    ta: "பொன்னான நேரத்தில் 1930 எண்ணை அழையுங்கள்: ஆன்லைன் மோசடியில் பணம் இழந்தால் 2 மணி நேரத்திற்குள் 1930 எண்ணை அழைத்து பணத்தை முடக்கவும்."
  }
];

/* ==========================================================================
   7. INTERACTIVE SCAM DEFENSE QUIZ DATA
   ========================================================================== */

const QuizQuestions = [
  {
    id: 1,
    category: "Banking Security",
    question: "You receive an SMS: 'Your Electricity power will be disconnected at 9:30 PM due to unpaid bill. Call officer at 9876543210 immediately.' What is the safest action?",
    options: [
      { text: "Call the number immediately to avoid power cutoff", correct: false },
      { text: "Ignore the SMS and check bill status on the official electricity portal/app", correct: true },
      { text: "Forward the message to your neighbors", correct: false },
      { text: "Download the APK file sent by the officer to verify payment", correct: false }
    ],
    explanation: "This is a widespread electricity bill smishing trap. Power distribution boards (like TANGEDCO) never send disconnect warnings from 10-digit personal mobile numbers or instruct customers to call private numbers."
  },
  {
    id: 2,
    category: "UPI & Digital Payments",
    question: "A buyer on an online marketplace (OLX) agrees to buy your sofa and sends a QR code saying: 'Scan this QR code and enter your UPI PIN to receive ₹15,000 in your account.' Is this safe?",
    options: [
      { text: "Yes, scanning QR codes is the standard way to accept UPI payments", correct: false },
      { text: "Yes, but only if you enter a 4-digit PIN instead of a 6-digit PIN", correct: false },
      { text: "No! Entering your UPI PIN will immediately DEDUCT ₹15,000 from your account", correct: true },
      { text: "Safe only if the payment app is Google Pay", correct: false }
    ],
    explanation: "Golden Rule of UPI: Entering a UPI PIN always transfers money OUT of your bank account. You NEVER need to enter a PIN or scan a QR code to receive money."
  },
  {
    id: 3,
    category: "Work-From-Home Scams",
    question: "You receive a Telegram message: 'Earn ₹3,000 per day by rating hotels on Google Maps. Pay ₹500 registration fee to activate your VIP worker account.' What is happening?",
    options: [
      { text: "A genuine digital marketing gig with standard onboarding fee", correct: false },
      { text: "A classic task-based scam. Once you pay, they demand larger deposits and never pay you", correct: true },
      { text: "A government-approved startup initiative", correct: false },
      { text: "A test task to evaluate your financial trust", correct: false }
    ],
    explanation: "Legitimate employers never charge job seekers an upfront registration fee or deposit. These Telegram task scams lure victims with small initial payouts before stealing thousands."
  },
  {
    id: 4,
    category: "Call & OTP Defense",
    question: "A polite caller claiming to be from your bank's fraud detection division says: 'We blocked an unauthorized ₹25,000 charge on your card. Read out the 6-digit OTP sent to your phone to reverse the charge.' What should you do?",
    options: [
      { text: "Read the OTP quickly before the charge is completed", correct: false },
      { text: "Refuse to share the OTP, disconnect the call, and call the official bank helpline directly", correct: true },
      { text: "Share only the first 3 digits of the OTP", correct: false },
      { text: "Ask the caller to read their bank employee ID card first", correct: false }
    ],
    explanation: "The caller is the fraudster who just triggered an unauthorized transaction. The OTP sent to your phone is the final authorization step to steal your money. Real bank staff will NEVER ask for your OTP."
  },
  {
    id: 5,
    category: "Tamil Phishing Alert",
    question: "நீங்கள் இந்த குறுஞ்செய்தியை பெறுகிறீர்கள்: 'உங்கள் வங்கி கணக்கு இன்று முடக்கப்படும். உடனே இந்த லிங்கை கிளிக் செய்து அப்டேட் செய்யவும்.' முதலில் நீங்கள் என்ன செய்ய வேண்டும்?",
    options: [
      { text: "உடனே லிங்கை கிளிக் செய்து விவரங்களை பூர்த்தி செய்ய வேண்டும்", correct: false },
      { text: "லிங்கை கிளிக் செய்யாமல் புறக்கணித்து, வங்கியின் அதிகாரப்பூர்வ தளத்தை சரிபார்க்க வேண்டும்", correct: true },
      { text: "செய்தியை குடும்ப குழுக்களில் பகிர வேண்டும்", correct: false },
      { text: "அந்த எண்ணிற்கு போன் செய்து OTP கொடுக்க வேண்டும்", correct: false }
    ],
    explanation: "வங்கிகள் ஒருபோதும் குறுஞ்செய்தியில் லிங்க் அனுப்பி கணக்கு முடக்கப்படும் என அச்சுறுத்த மாட்டார்கள். லிங்கை தொடாமல் நேரடியாக வங்கியின் அதிகாரப்பூர்வ செயலி அல்லது கிளைக்கு சென்று சரிபார்க்கவும்."
  }
];

/* ==========================================================================
   8. APPLICATION CONTROLLER
   ========================================================================== */

const App = {
  activeSection: 'dashboard',
  currentTipIndex: 0,
  quizCurrentIndex: 0,
  quizScore: 0,
  quizAnswered: false,
  speechRecognition: null,
  isRecordingVoice: false,
  pendingDeleteId: null,

  init() {
    if (!document.getElementById('section-dashboard')) {
      return;
    }

    this.setupNavigation();
    this.setupMessageAnalyzer();
    this.setupUrlScanner();
    this.setupVoiceAnalyzer();
    this.setupAwarenessAndQuiz();
    this.setupTrends();
    this.setupHistory();
    this.setupTips();
    this.setupModal();

    // Sync state
    this.updateDashboardStats();
    this.renderRecentDashboardList();

    // Handle initial hash navigation
    const hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById(`section-${hash}`)) {
      this.navigateTo(hash);
    } else {
      this.navigateTo('dashboard');
    }
  },

  /* ------------------------------------------------------------------------
     NAVIGATION SYSTEM
     ------------------------------------------------------------------------ */
  setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const mobileToggle = document.getElementById('mobile-nav-toggle');
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');

    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const sectionId = link.getAttribute('data-section');
        this.navigateTo(sectionId);

        // Close mobile drawer if open
        if (sidebar.classList.contains('open')) {
          this.toggleMobileNav(false);
        }
      });
    });

    if (mobileToggle) {
      mobileToggle.addEventListener('click', () => {
        const isOpen = sidebar.classList.contains('open');
        this.toggleMobileNav(!isOpen);
      });
    }

    if (backdrop) {
      backdrop.addEventListener('click', () => {
        this.toggleMobileNav(false);
      });
    }

    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '');
      if (hash && hash !== this.activeSection && document.getElementById(`section-${hash}`)) {
        this.navigateTo(hash, false);
      }
    });
  },

  toggleMobileNav(open) {
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    const toggle = document.getElementById('mobile-nav-toggle');

    if (open) {
      sidebar.classList.add('open');
      backdrop.classList.add('active');
      toggle.setAttribute('aria-expanded', 'true');
    } else {
      sidebar.classList.remove('open');
      backdrop.classList.remove('active');
      toggle.setAttribute('aria-expanded', 'false');
    }
  },

  navigateTo(sectionId, updateHash = true) {
    const targetSection = document.getElementById(`section-${sectionId}`);
    if (!targetSection) return;

    // Switch section view
    document.querySelectorAll('.content-section').forEach(sec => sec.classList.remove('active'));
    targetSection.classList.add('active');

    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
      if (link.getAttribute('data-section') === sectionId) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    this.activeSection = sectionId;
    if (updateHash) {
      window.location.hash = sectionId;
    }

    // Scroll to top of stage
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Refresh context data when entering section
    if (sectionId === 'dashboard') {
      this.updateDashboardStats();
      this.renderRecentDashboardList();
    } else if (sectionId === 'trends') {
      this.renderTrends();
    } else if (sectionId === 'history') {
      this.renderHistoryRecords();
    }
  },

  /* ------------------------------------------------------------------------
     MESSAGE ANALYZER SYSTEM
     ------------------------------------------------------------------------ */
  setupMessageAnalyzer() {
    const input = document.getElementById('message-input');
    const charCounter = document.getElementById('char-counter');
    const btnAnalyze = document.getElementById('btn-analyze-msg');
    const btnClear = document.getElementById('btn-clear-msg');
    const btnCopyAdvice = document.getElementById('btn-copy-advice');
    const validationMsg = document.getElementById('input-validation-msg');
    if (!input || !charCounter || !btnAnalyze || !btnClear) return;

    // Character counter
    input.addEventListener('input', () => {
      charCounter.textContent = input.value.length;
      if (validationMsg && !validationMsg.classList.contains('hidden')) {
        validationMsg.classList.add('hidden');
      }
    });

    // Preset messages mapping
    const Presets = {
      en_bank: "Your bank account will be blocked today. Click this link and enter your OTP immediately.",
      ta_bank: "உங்கள் வங்கி கணக்கு இன்று முடக்கப்படும். உடனே இந்த லிங்கை கிளிக் செய்து OTP கொடுக்கவும்.",
      tanglish_bank: "Ungal bank account block aagapoguthu. Indha link click panni OTP enter pannunga.",
      upi_cashback: "Congratulations! You received ₹25,000 cashback from GooglePay. Scan this QR code and enter your UPI PIN to claim reward.",
      job_scam: "Part-time work from home! Earn Rs.5000 daily by liking YouTube videos. Pay Rs.500 registration fee on Telegram to start.",
      safe_msg: "Hi mom, let's meet for lunch at 1pm tomorrow. Have a great day!"
    };

    document.querySelectorAll('.btn-preset[data-example]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-example');
        if (Presets[key]) {
          input.value = Presets[key];
          charCounter.textContent = input.value.length;
          validationMsg.classList.add('hidden');
          this.triggerMessageScan(Presets[key]);
        }
      });
    });

    btnClear.addEventListener('click', () => {
      this.resetAnalyzer();
    });

    btnAnalyze.addEventListener('click', () => {
      const text = input.value.trim();
      if (!text) {
        validationMsg.textContent = "Please enter or paste a message to analyze.";
        validationMsg.classList.remove('hidden');
        input.focus();
        return;
      }
      validationMsg.classList.add('hidden');
      this.triggerMessageScan(text);
    });

    if (btnCopyAdvice) {
      btnCopyAdvice.addEventListener('click', () => {
        this.copySafetyAdvice();
      });
    }
  },

  resetAnalyzer() {
    const input = document.getElementById('message-input');
    input.value = '';
    document.getElementById('char-counter').textContent = '0';
    document.getElementById('input-validation-msg').classList.add('hidden');
    document.getElementById('analysis-results-panel').classList.add('hidden');
    document.getElementById('scanning-progress').classList.add('hidden');
    input.focus();
  },

  triggerMessageScan(messageText) {
    const langSelect = document.getElementById('analyzer-lang-select');
    const scanningBox = document.getElementById('scanning-progress');
    const resultsPanel = document.getElementById('analysis-results-panel');
    const statusText = document.getElementById('scanner-status-text');

    resultsPanel.classList.add('hidden');
    scanningBox.classList.remove('hidden');

    const scanSteps = [
      "Tokenizing multilingual script patterns...",
      "Executing heuristic threat vectors...",
      "Evaluating urgency and credential requests...",
      "Compiling cybersecurity assessment report..."
    ];

    let stepIndex = 0;
    const interval = setInterval(() => {
      stepIndex++;
      if (stepIndex < scanSteps.length) {
        statusText.textContent = scanSteps[stepIndex];
      } else {
        clearInterval(interval);
        scanningBox.classList.add('hidden');

        // Execute Detection Engine
        const selectedLang = langSelect ? langSelect.value : 'auto';
        const result = ScamShieldEngine.analyze(messageText, selectedLang);

        this.renderAnalysisResult(result);

        // Save to Audit Log
        const record = {
          id: 'scan_' + Date.now(),
          timestamp: new Date().toISOString(),
          score: result.score,
          riskLevel: result.riskLevel,
          category: result.category,
          language: result.detectedLanguage,
          // Store only privacy-conscious preview (first 65 chars)
          snippet: messageText.length > 65 ? messageText.substring(0, 65) + '...' : messageText
        };
        StorageManager.save(record);
        this.updateDashboardStats();
      }
    }, 180);
  },

  renderAnalysisResult(result) {
    const resultsPanel = document.getElementById('analysis-results-panel');
    const scoreNum = document.getElementById('result-score-num');
    const meterFill = document.getElementById('risk-meter-fill');
    const riskBadge = document.getElementById('result-risk-badge');
    const catBadge = document.getElementById('result-category-badge');
    const langBadge = document.getElementById('result-lang-badge');
    const verdictTitle = document.getElementById('result-verdict-title');
    const verdictDesc = document.getElementById('result-verdict-desc');
    const warningCount = document.getElementById('result-warning-count');
    const highlightedContainer = document.getElementById('highlighted-message-display');
    const phrasesList = document.getElementById('detected-phrases-list');
    const recsList = document.getElementById('safety-recommendations-list');

    // 1. Score & Radial Meter Animation
    scoreNum.textContent = result.score;
    // Circular perimeter = 2 * PI * 66 ≈ 414.69
    const perimeter = 414.69;
    const offset = perimeter - (result.score / 100) * perimeter;
    meterFill.style.strokeDashoffset = offset;

    // Color coding based on risk
    meterFill.classList.remove('meter-safe', 'meter-warn', 'meter-danger');
    riskBadge.className = 'risk-badge';

    if (result.riskLevel === 'high') {
      meterFill.style.stroke = '#ef4444';
      riskBadge.classList.add('high');
      riskBadge.textContent = 'HIGH RISK';
    } else if (result.riskLevel === 'medium') {
      meterFill.style.stroke = '#f59e0b';
      riskBadge.classList.add('med');
      riskBadge.textContent = 'MEDIUM RISK';
    } else {
      meterFill.style.stroke = '#10b981';
      riskBadge.classList.add('low');
      riskBadge.textContent = 'LOW RISK';
    }

    catBadge.textContent = result.category;
    langBadge.textContent = result.detectedLanguage;
    verdictTitle.textContent = result.verdictTitle;
    verdictDesc.textContent = result.verdictDescription;
    warningCount.textContent = `${result.warningSigns.length} threat indicator${result.warningSigns.length === 1 ? '' : 's'}`;

    // 2. Safe DOM Highlighting (Zero XSS vulnerability)
    this.renderSafeHighlightedText(highlightedContainer, result.analyzedText, result.highlights);

    // 3. Detected Threat Explanations List
    phrasesList.innerHTML = '';
    if (result.warningSigns.length === 0) {
      phrasesList.innerHTML = `
        <div class="threat-item-card safe">
          <div class="threat-card-top">
            <span class="threat-category-tag" style="color:#34d399;">Clean Heuristics</span>
            <span class="threat-weight-pill" style="background:rgba(16,185,129,0.15); color:#34d399; border-color:rgba(16,185,129,0.3);">Weight: 0</span>
          </div>
          <div class="threat-explanation">
            No known phishing patterns, high-pressure threats, or credential harvest vectors were found in this text.
          </div>
        </div>
      `;
    } else {
      result.warningSigns.forEach(sign => {
        const card = document.createElement('div');
        card.className = `threat-item-card ${sign.severity === 'high' ? 'danger' : 'warn'}`;
        card.innerHTML = `
          <div class="threat-card-top">
            <span class="threat-category-tag">${this.escapeHtml(sign.title)}</span>
            <span class="threat-weight-pill">Severity: ${sign.weight} pts</span>
          </div>
          <div class="threat-detected-phrase">
            Trigger Match: <mark>${this.escapeHtml(sign.detectedPhrase)}</mark>
          </div>
          <div class="threat-explanation">
            ${this.escapeHtml(sign.explanation)}
          </div>
          <div class="threat-defense-tip">
            <strong>Actionable defense:</strong> ${this.escapeHtml(sign.advice)}
          </div>
        `;
        phrasesList.appendChild(card);
      });
    }

    // 4. Personalized Recommendations Checklist
    recsList.innerHTML = '';
    result.recommendations.forEach(rec => {
      const item = document.createElement('div');
      item.className = 'safety-check-item';
      item.innerHTML = `
        <span class="safety-check-icon">
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        </span>
        <span>${this.escapeHtml(rec)}</span>
      `;
      recsList.appendChild(item);
    });

    resultsPanel.classList.remove('hidden');
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },

  /**
   * Safely constructs DOM text nodes and mark elements without unescaped innerHTML
   */
  renderSafeHighlightedText(container, fullText, intervals) {
    container.innerHTML = '';

    if (!intervals || intervals.length === 0) {
      container.appendChild(document.createTextNode(fullText));
      return;
    }

    let currentIndex = 0;

    intervals.forEach(range => {
      // 1. Text before highlight
      if (range.start > currentIndex) {
        const plainText = fullText.substring(currentIndex, range.start);
        container.appendChild(document.createTextNode(plainText));
      }

      // 2. Highlighted mark element
      const mark = document.createElement('mark');
      mark.className = range.severity === 'high' ? 'scam-highlight' : 'scam-highlight-med';
      mark.textContent = fullText.substring(range.start, range.end);
      container.appendChild(mark);

      currentIndex = range.end;
    });

    // 3. Trailing text after final highlight
    if (currentIndex < fullText.length) {
      const trailing = fullText.substring(currentIndex);
      container.appendChild(document.createTextNode(trailing));
    }
  },

  copySafetyAdvice() {
    const items = document.querySelectorAll('#safety-recommendations-list .safety-check-item');
    if (!items.length) {
      this.showToast("No advice available to copy", "danger");
      return;
    }

    const textArr = [];
    textArr.push("🛡️ ScamShield AI Safety Recommendations:");
    items.forEach((item, index) => {
      textArr.push(`${index + 1}. ${item.innerText.trim()}`);
    });
    textArr.push("\nNational Cyber Crime Helpline (India): Dial 1930 | cybercrime.gov.in");

    const fullAdvice = textArr.join("\n");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(fullAdvice).then(() => {
        this.showToast("Safety recommendations copied to clipboard!", "safe");
      }).catch(() => {
        this.fallbackCopy(fullAdvice);
      });
    } else {
      this.fallbackCopy(fullAdvice);
    }
  },

  fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      this.showToast("Safety recommendations copied to clipboard!", "safe");
    } catch {
      this.showToast("Failed to copy advice automatically", "danger");
    }
    document.body.removeChild(textarea);
  },

  /* ------------------------------------------------------------------------
     URL SCANNER SYSTEM
     ------------------------------------------------------------------------ */
  setupUrlScanner() {
    const urlInput = document.getElementById('url-input');
    const btnScanUrl = document.getElementById('btn-scan-url');
    const validationMsg = document.getElementById('url-validation-msg');
    if (!urlInput || !btnScanUrl) return;

    const UrlPresets = {
      ip_host: "http://192.168.1.50/sbi-verify.html",
      shortener: "http://bit.ly/claim-free-iphone-2026",
      lookalike: "https://sbi.netbanking-kyc.xyz/login",
      safe: "https://www.onlinesbi.sbi"
    };

    document.querySelectorAll('.btn-preset[data-url-example]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-url-example');
        if (UrlPresets[key]) {
          urlInput.value = UrlPresets[key];
          validationMsg.classList.add('hidden');
          this.triggerUrlScan(UrlPresets[key]);
        }
      });
    });

    btnScanUrl.addEventListener('click', () => {
      const url = urlInput.value.trim();
      if (!url) {
        validationMsg.textContent = "Please enter a URL to inspect.";
        validationMsg.classList.remove('hidden');
        urlInput.focus();
        return;
      }
      validationMsg.classList.add('hidden');
      this.triggerUrlScan(url);
    });
  },

  triggerUrlScan(url) {
    const resultsPanel = document.getElementById('url-results-panel');
    const res = UrlScannerEngine.scan(url);

    // Update UI elements
    const scoreNum = document.getElementById('url-score-num');
    const meterFill = document.getElementById('url-risk-meter-fill');
    const riskBadge = document.getElementById('url-risk-badge');
    const protocolBadge = document.getElementById('url-protocol-badge');
    const title = document.getElementById('url-verdict-title');
    const targetDisplay = document.getElementById('url-display-target');
    const desc = document.getElementById('url-verdict-desc');
    const indicatorsList = document.getElementById('url-indicators-list');
    const adviceList = document.getElementById('url-advice-list');

    scoreNum.textContent = res.score;
    const perimeter = 414.69;
    meterFill.style.strokeDashoffset = perimeter - (res.score / 100) * perimeter;

    riskBadge.className = 'risk-badge';
    if (res.riskLevel === 'high') {
      meterFill.style.stroke = '#ef4444';
      riskBadge.classList.add('high');
      riskBadge.textContent = 'HIGH RISK';
    } else if (res.riskLevel === 'medium') {
      meterFill.style.stroke = '#f59e0b';
      riskBadge.classList.add('med');
      riskBadge.textContent = 'MEDIUM RISK';
    } else {
      meterFill.style.stroke = '#10b981';
      riskBadge.classList.add('low');
      riskBadge.textContent = 'LOW RISK';
    }

    protocolBadge.textContent = res.protocol;
    title.textContent = res.verdictTitle;
    targetDisplay.textContent = res.url;
    desc.textContent = res.verdictDesc;

    // Render detected indicators
    indicatorsList.innerHTML = '';
    if (res.indicators.length === 0) {
      indicatorsList.innerHTML = `
        <div class="threat-item-card safe">
          <div class="threat-card-top">
            <span class="threat-category-tag" style="color:#34d399;">Clean URL Syntax</span>
            <span class="threat-weight-pill" style="background:rgba(16,185,129,0.15); color:#34d399; border-color:rgba(16,185,129,0.3);">Safe</span>
          </div>
          <div class="threat-explanation">
            No malicious IP hostnames, high-abuse TLDs, or brand impersonation tokens detected in this URL.
          </div>
        </div>
      `;
    } else {
      res.indicators.forEach(ind => {
        const item = document.createElement('div');
        item.className = `threat-item-card ${ind.severity === 'high' ? 'danger' : 'warn'}`;
        item.innerHTML = `
          <div class="threat-card-top">
            <span class="threat-category-tag">${this.escapeHtml(ind.title)}</span>
            <span class="threat-weight-pill">${ind.severity === 'high' ? 'Critical Vector' : 'Warning'}</span>
          </div>
          <div class="threat-explanation">${this.escapeHtml(ind.desc)}</div>
        `;
        indicatorsList.appendChild(item);
      });
    }

    // Render advice
    adviceList.innerHTML = '';
    res.advice.forEach(adv => {
      const item = document.createElement('div');
      item.className = 'safety-check-item';
      item.innerHTML = `
        <span class="safety-check-icon">
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        </span>
        <span>${this.escapeHtml(adv)}</span>
      `;
      adviceList.appendChild(item);
    });

    resultsPanel.classList.remove('hidden');
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },

  /* ------------------------------------------------------------------------
     VOICE ANALYSIS SYSTEM
     ------------------------------------------------------------------------ */
  setupVoiceAnalyzer() {
    const banner = document.getElementById('voice-support-banner');
    const btnToggleMic = document.getElementById('btn-toggle-mic');
    const micPulse = document.getElementById('mic-ring-pulse');
    const statusLabel = document.getElementById('mic-status-label');
    const langSelect = document.getElementById('voice-lang-select');
    const transcriptInput = document.getElementById('voice-transcript-input');
    const btnClearVoice = document.getElementById('btn-clear-voice');
    const btnAnalyzeVoice = document.getElementById('btn-analyze-voice');
    if (!banner || !btnToggleMic) return;

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

    if (SpeechRecognition) {
      banner.className = 'voice-support-banner supported';
      banner.innerHTML = `
        <strong>✓ Web Speech API Available:</strong> You can click the microphone button to dictate a suspicious phone call script in Tamil or English in supported browsers (Google Chrome).
      `;

      this.speechRecognition = new SpeechRecognition();
      this.speechRecognition.continuous = true;
      this.speechRecognition.interimResults = true;

      this.speechRecognition.onresult = (event) => {
        let finalTrans = '';
        for (let i = event.resultIndex; i < event.results.length; i++) {
          finalTrans += event.results[i][0].transcript;
        }
        transcriptInput.value = (transcriptInput.value + ' ' + finalTrans).trim();
      };

      this.speechRecognition.onerror = (event) => {
        statusLabel.textContent = `Mic Error: ${event.error}. You can still paste or type text manually.`;
        this.stopVoiceRecording();
      };

      this.speechRecognition.onend = () => {
        if (this.isRecordingVoice) {
          this.stopVoiceRecording();
        }
      };
    } else {
      banner.className = 'voice-support-banner unsupported';
      banner.innerHTML = `
        <strong>⚠️ Web Speech API Not Supported:</strong> Live audio recording is not available in your current browser configuration. You can paste or type transcribed call audio scripts into the box below to run complete threat analysis.
      `;
    }

    // Toggle Mic Button
    btnToggleMic.addEventListener('click', () => {
      if (!this.speechRecognition) {
        this.showToast("Speech recognition is not supported in this browser. Please type or paste text manually.", "warn");
        return;
      }

      if (this.isRecordingVoice) {
        this.stopVoiceRecording();
      } else {
        this.startVoiceRecording();
      }
    });

    // Voice Presets
    const VoicePresets = {
      police_extortion: "Hello, this is CBI Officer Vikram calling from Delhi Cyber Cell. An illegal package with drugs and fake passports was seized in Mumbai under your Aadhaar name. An arrest warrant is issued. Do not disconnect this call or you will be arrested immediately.",
      ta_electricity: "வணக்கம் மின்சார வாரியத்தில் இருந்து பேசுகிறேன். உங்கள் மின் கட்டணம் நிலுவையில் உள்ளதால் இன்று இரவு 9 மணிக்கு கரண்ட் கட் செய்யப்படும். உடனே பில் அப்டேட் செய்ய OTP சொல்லவும்.",
      courier_customs: "Sir India Post parcel vandhurukku. Ungal address incomplete aaga irukku. Re-delivery fee kattala na parcel confiscate panniduvanga."
    };

    document.querySelectorAll('.btn-preset[data-voice-preset]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-voice-preset');
        if (VoicePresets[key]) {
          transcriptInput.value = VoicePresets[key];
        }
      });
    });

    btnClearVoice.addEventListener('click', () => {
      transcriptInput.value = '';
      document.getElementById('voice-results-panel').classList.add('hidden');
    });

    btnAnalyzeVoice.addEventListener('click', () => {
      const text = transcriptInput.value.trim();
      if (!text) {
        this.showToast("Please transcribe or enter voice text to analyze.", "warn");
        transcriptInput.focus();
        return;
      }

      // Jump over to standard analysis presentation
      this.triggerMessageScan(text);
      this.navigateTo('analyze');
    });
  },

  startVoiceRecording() {
    const btnToggleMic = document.getElementById('btn-toggle-mic');
    const micPulse = document.getElementById('mic-ring-pulse');
    const statusLabel = document.getElementById('mic-status-label');
    const langSelect = document.getElementById('voice-lang-select');

    try {
      this.speechRecognition.lang = langSelect.value || 'en-IN';
      this.speechRecognition.start();
      this.isRecordingVoice = true;
      btnToggleMic.classList.add('recording');
      micPulse.classList.add('active');
      statusLabel.textContent = "Listening... Speak clearly into microphone (Click to stop)";
    } catch {
      this.stopVoiceRecording();
    }
  },

  stopVoiceRecording() {
    const btnToggleMic = document.getElementById('btn-toggle-mic');
    const micPulse = document.getElementById('mic-ring-pulse');
    const statusLabel = document.getElementById('mic-status-label');

    if (this.speechRecognition && this.isRecordingVoice) {
      try { this.speechRecognition.stop(); } catch {}
    }
    this.isRecordingVoice = false;
    btnToggleMic.classList.remove('recording');
    micPulse.classList.remove('active');
    statusLabel.textContent = "Click Microphone to Start Listening";
  },

  /* ------------------------------------------------------------------------
     AWARENESS & QUIZ SYSTEM
     ------------------------------------------------------------------------ */
  setupAwarenessAndQuiz() {
    const qIndexEl = document.getElementById('quiz-q-index');
    if (!qIndexEl) return;
    this.renderQuizQuestion();

    const btnNext = document.getElementById('btn-next-question');
    const btnRestart = document.getElementById('btn-restart-quiz');
    if (!btnNext || !btnRestart) return;

    btnNext.addEventListener('click', () => {
      this.quizCurrentIndex++;
      if (this.quizCurrentIndex >= QuizQuestions.length) {
        this.finishQuiz();
      } else {
        this.renderQuizQuestion();
      }
    });

    btnRestart.addEventListener('click', () => {
      this.quizCurrentIndex = 0;
      this.quizScore = 0;
      document.getElementById('quiz-score-display').textContent = `0 / ${QuizQuestions.length}`;
      document.getElementById('quiz-complete-card').classList.add('hidden');
      document.getElementById('quiz-stage').classList.remove('hidden');
      this.renderQuizQuestion();
    });
  },

  renderQuizQuestion() {
    this.quizAnswered = false;
    const q = QuizQuestions[this.quizCurrentIndex];

    const qIndexEl = document.getElementById('quiz-q-index');
    const qCategoryEl = document.getElementById('quiz-q-category');
    const qTextEl = document.getElementById('quiz-q-text');
    const optionsContainer = document.getElementById('quiz-options-list');
    const feedbackBox = document.getElementById('quiz-feedback-box');
    const progressFill = document.getElementById('quiz-progress-fill');

    feedbackBox.classList.add('hidden');
    qIndexEl.textContent = `Question ${this.quizCurrentIndex + 1} of ${QuizQuestions.length}`;
    qCategoryEl.textContent = q.category;
    qTextEl.textContent = q.question;

    const progressPct = ((this.quizCurrentIndex + 1) / QuizQuestions.length) * 100;
    progressFill.style.width = `${progressPct}%`;

    optionsContainer.innerHTML = '';
    const letters = ['A', 'B', 'C', 'D'];

    q.options.forEach((opt, idx) => {
      const btn = document.createElement('button');
      btn.className = 'quiz-option-btn';
      btn.innerHTML = `
        <span class="quiz-option-prefix">${letters[idx]}</span>
        <span>${this.escapeHtml(opt.text)}</span>
      `;

      btn.addEventListener('click', () => {
        if (this.quizAnswered) return;
        this.handleQuizSelection(opt, btn, q);
      });

      optionsContainer.appendChild(btn);
    });
  },

  handleQuizSelection(selectedOption, chosenButton, questionData) {
    this.quizAnswered = true;
    const allButtons = document.querySelectorAll('.quiz-option-btn');
    allButtons.forEach(btn => btn.disabled = true);

    const feedbackBox = document.getElementById('quiz-feedback-box');
    const feedbackIcon = document.getElementById('feedback-icon');
    const feedbackTitle = document.getElementById('feedback-title');
    const feedbackExpl = document.getElementById('feedback-explanation');
    const scoreDisplay = document.getElementById('quiz-score-display');

    if (selectedOption.correct) {
      this.quizScore++;
      chosenButton.classList.add('correct');
      feedbackIcon.textContent = '✓';
      feedbackIcon.style.color = '#34d399';
      feedbackTitle.textContent = 'Spot On! Correct Answer';
      feedbackTitle.style.color = '#34d399';
    } else {
      chosenButton.classList.add('incorrect');
      // Highlight the correct one
      allButtons.forEach((btn, index) => {
        if (questionData.options[index].correct) {
          btn.classList.add('correct');
        }
      });
      feedbackIcon.textContent = '✕';
      feedbackIcon.style.color = '#f87171';
      feedbackTitle.textContent = 'Caution: Vulnerable Choice';
      feedbackTitle.style.color = '#f87171';
    }

    scoreDisplay.textContent = `${this.quizScore} / ${QuizQuestions.length}`;
    feedbackExpl.textContent = questionData.explanation;
    feedbackBox.classList.remove('hidden');
  },

  finishQuiz() {
    document.getElementById('quiz-stage').classList.add('hidden');
    const completeCard = document.getElementById('quiz-complete-card');
    const finalScoreEl = document.getElementById('quiz-final-score-text');
    const verdictEl = document.getElementById('quiz-complete-verdict');

    finalScoreEl.textContent = `You scored ${this.quizScore} out of ${QuizQuestions.length}`;
    if (this.quizScore === 5) {
      verdictEl.textContent = "Outstanding reflexes! You demonstrated exceptional cyber threat awareness and are well prepared to protect yourself and family from modern scammers.";
    } else if (this.quizScore >= 3) {
      verdictEl.textContent = "Good awareness! You spotted most scams but should stay extra cautious with banking OTPs and deceptive urgency tactics.";
    } else {
      verdictEl.textContent = "Caution advised! Review our 8 scam awareness knowledge cards above to learn how modern cyber syndicates operate.";
    }

    completeCard.classList.remove('hidden');
  },

  /* ------------------------------------------------------------------------
     SCAM TRENDS & TELEMETRY
     ------------------------------------------------------------------------ */
  setupTrends() {
    const demoToggle = document.getElementById('toggle-demo-data');
    if (demoToggle) {
      demoToggle.addEventListener('change', () => {
        this.renderTrends();
      });
    }
  },

  renderTrends() {
    const demoToggle = document.getElementById('toggle-demo-data');
    const sourceText = document.getElementById('trends-source-text');
    const isDemo = demoToggle && demoToggle.checked;

    let stats;
    if (isDemo) {
      stats = DemoTelemetry.stats;
      sourceText.textContent = "Showing demonstration telemetry dataset for hackathon review. (Not live cybercrime statistics).";
    } else {
      stats = StorageManager.getStats();
      sourceText.textContent = "Showing actual analyses performed inside this browser session & storage.";
    }

    const total = stats.total || 0;

    // Severity Percentages
    const lowPct = total ? Math.round((stats.low / total) * 100) : 0;
    const medPct = total ? Math.round((stats.medium / total) * 100) : 0;
    const highPct = total ? Math.round((stats.high / total) * 100) : 0;

    document.getElementById('trend-pct-low').textContent = `${lowPct}% (${stats.low})`;
    document.getElementById('trend-pct-med').textContent = `${medPct}% (${stats.medium})`;
    document.getElementById('trend-pct-high').textContent = `${highPct}% (${stats.high})`;

    document.getElementById('trend-bar-low').style.width = `${lowPct}%`;
    document.getElementById('trend-bar-med').style.width = `${medPct}%`;
    document.getElementById('trend-bar-high').style.width = `${highPct}%`;

    // Language Percentages
    const enCount = stats.languages['English'] || 0;
    const taCount = stats.languages['Tamil (தமிழ்)'] || 0;
    const tanglishCount = stats.languages['Tanglish'] || 0;

    const enPct = total ? Math.round((enCount / total) * 100) : 0;
    const taPct = total ? Math.round((taCount / total) * 100) : 0;
    const tanglishPct = total ? Math.round((tanglishCount / total) * 100) : 0;

    document.getElementById('trend-lang-en').textContent = `${enPct}% (${enCount})`;
    document.getElementById('trend-lang-ta').textContent = `${taPct}% (${taCount})`;
    document.getElementById('trend-lang-tanglish').textContent = `${tanglishPct}% (${tanglishCount})`;

    document.getElementById('trend-bar-lang-en').style.width = `${enPct}%`;
    document.getElementById('trend-bar-lang-ta').style.width = `${taPct}%`;
    document.getElementById('trend-bar-lang-tanglish').style.width = `${tanglishPct}%`;

    // Top Scam Categories
    const categoriesContainer = document.getElementById('scam-types-trend-list');
    categoriesContainer.innerHTML = '';

    const catEntries = Object.entries(stats.categories).sort((a, b) => b[1] - a[1]);
    if (catEntries.length === 0) {
      categoriesContainer.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1; padding: 2rem 1rem;">
          <p class="empty-state-title">No Scan Telemetry Available</p>
          <p class="empty-state-desc">Analyze messages in the Message Analyzer or switch on 'Load Demonstration Telemetry' above to view sample distribution graphs.</p>
        </div>
      `;
    } else {
      catEntries.forEach(([cat, count]) => {
        const catPct = total ? Math.round((count / total) * 100) : 0;
        const card = document.createElement('div');
        card.className = 'scam-type-stat-card';
        card.innerHTML = `
          <div class="scam-type-name">${this.escapeHtml(cat)}</div>
          <div class="scam-type-count">${count}</div>
          <div class="scam-type-pct">${catPct}% of total scans</div>
        `;
        categoriesContainer.appendChild(card);
      });
    }
  },

  /* ------------------------------------------------------------------------
     ANALYSIS HISTORY SYSTEM
     ------------------------------------------------------------------------ */
  setupHistory() {
    const searchInput = document.getElementById('history-search-input');
    const filterPills = document.querySelectorAll('#history-filter-pills .filter-pill');
    const btnClearAll = document.getElementById('btn-clear-history');
    const btnExport = document.getElementById('btn-export-history');

    if (searchInput) {
      searchInput.addEventListener('input', () => {
        this.renderHistoryRecords();
      });
    }

    filterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        filterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        this.renderHistoryRecords();
      });
    });

    if (btnClearAll) {
      btnClearAll.addEventListener('click', () => {
        this.openConfirmModal(
          "Clear All History",
          "Are you sure you want to delete all saved analysis history? This action cannot be undone.",
          () => {
            StorageManager.clearAll();
            this.renderHistoryRecords();
            this.updateDashboardStats();
            this.renderRecentDashboardList();
            this.showToast("All analysis history cleared successfully.", "safe");
          }
        );
      });
    }

    if (btnExport) {
      btnExport.addEventListener('click', () => {
        this.exportHistoryLog();
      });
    }
  },

  renderHistoryRecords() {
    const container = document.getElementById('history-records-container');
    const searchInput = document.getElementById('history-search-input');
    const activePill = document.querySelector('#history-filter-pills .filter-pill.active');

    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const filter = activePill ? activePill.getAttribute('data-filter') : 'all';

    const allRecords = StorageManager.getAll();

    const filtered = allRecords.filter(item => {
      // Risk filter
      if (filter !== 'all' && item.riskLevel !== filter) return false;

      // Search keyword filter
      if (query) {
        const textMatch = (item.snippet || '').toLowerCase().includes(query);
        const catMatch = (item.category || '').toLowerCase().includes(query);
        const langMatch = (item.language || '').toLowerCase().includes(query);
        return textMatch || catMatch || langMatch;
      }
      return true;
    });

    container.innerHTML = '';
    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" width="40" height="40" stroke="currentColor" stroke-width="1.5" fill="none">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
          </div>
          <p class="empty-state-title">No Analysis Records Found</p>
          <p class="empty-state-desc">${allRecords.length === 0 ? "You haven't analyzed any messages yet. Analyzed messages will be saved locally here." : "No records match your search or filter criteria."}</p>
        </div>
      `;
      return;
    }

    filtered.forEach(item => {
      const card = document.createElement('div');
      card.className = 'history-record-card';

      const dateStr = new Date(item.timestamp).toLocaleString();
      const riskClass = item.riskLevel === 'high' ? 'high' : (item.riskLevel === 'medium' ? 'med' : 'low');

      card.innerHTML = `
        <div class="record-left">
          <div class="record-score-box ${riskClass}">
            <span class="record-score-num">${item.score}</span>
            <span class="record-score-unit">RISK</span>
          </div>
          <div class="record-details">
            <div class="record-meta-line">
              <span class="record-category">${this.escapeHtml(item.category || 'Threat Assessment')}</span>
              <span class="record-lang">${this.escapeHtml(item.language || 'English')}</span>
              <span class="record-time">${dateStr}</span>
            </div>
            <div class="record-preview">${this.escapeHtml(item.snippet || '')}</div>
          </div>
        </div>
        <div class="record-actions">
          <button class="btn-icon-del" data-del-id="${item.id}" title="Delete record" aria-label="Delete this record">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
          </button>
        </div>
      `;

      const btnDel = card.querySelector('.btn-icon-del');
      btnDel.addEventListener('click', () => {
        StorageManager.deleteRecord(item.id);
        this.renderHistoryRecords();
        this.updateDashboardStats();
        this.renderRecentDashboardList();
        this.showToast("Record removed", "safe");
      });

      container.appendChild(card);
    });
  },

  exportHistoryLog() {
    const list = StorageManager.getAll();
    if (!list.length) {
      this.showToast("No analysis history to export", "warn");
      return;
    }

    const jsonStr = JSON.stringify(list, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scamshield-audit-log-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast("Audit log exported as JSON file", "safe");
  },

  /* ------------------------------------------------------------------------
     DASHBOARD LIVE METRICS & RECENT LIST
     ------------------------------------------------------------------------ */
  updateDashboardStats() {
    const stats = StorageManager.getStats();

    const elTotal = document.getElementById('dash-stat-total');
    const elLow = document.getElementById('dash-stat-low');
    const elMed = document.getElementById('dash-stat-med');
    const elHigh = document.getElementById('dash-stat-high');

    if (elTotal) elTotal.textContent = stats.total;
    if (elLow) elLow.textContent = stats.low;
    if (elMed) elMed.textContent = stats.medium;
    if (elHigh) elHigh.textContent = stats.high;
  },

  renderRecentDashboardList() {
    const container = document.getElementById('dash-recent-list');
    if (!container) return;

    const allRecords = StorageManager.getAll();
    const recent = allRecords.slice(0, 4);

    container.innerHTML = '';
    if (recent.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" width="36" height="36" stroke="currentColor" stroke-width="1.5" fill="none">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
          </div>
          <p class="empty-state-title">No Messages Analyzed Yet</p>
          <p class="empty-state-desc">Your recent scans will be tracked here in real-time. Click 'Analyze a Message' to run your first threat evaluation.</p>
        </div>
      `;
      return;
    }

    recent.forEach(item => {
      const row = document.createElement('div');
      row.className = 'recent-scan-item';

      const riskClass = item.riskLevel === 'high' ? 'badge-lang danger' : (item.riskLevel === 'medium' ? 'badge-lang warn' : 'badge-lang safe');
      const timeStr = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      row.innerHTML = `
        <div class="scan-left">
          <span class="${riskClass}">${item.riskLevel.toUpperCase()} (${item.score})</span>
          <span class="scan-text-preview">${this.escapeHtml(item.snippet || '')}</span>
        </div>
        <div class="scan-right">
          <span>${this.escapeHtml(item.category || '')}</span>
          <span>${timeStr}</span>
        </div>
      `;
      container.appendChild(row);
    });
  },

  /* ------------------------------------------------------------------------
     SAFETY TIPS SYSTEM
     ------------------------------------------------------------------------ */
  setupTips() {
    const btnNext = document.getElementById('btn-next-tip');
    if (btnNext) {
      btnNext.addEventListener('click', () => {
        this.currentTipIndex = (this.currentTipIndex + 1) % CyberSafetyTips.length;
        this.renderTip();
      });
    }
  },

  renderTip() {
    const tip = CyberSafetyTips[this.currentTipIndex];
    const tipContainer = document.getElementById('daily-tip-text');
    if (!tipContainer || !tip) return;

    tipContainer.innerHTML = `
      <p class="tip-en">${tip.en}</p>
      <p class="tip-ta">${tip.ta}</p>
    `;
  },

  /* ------------------------------------------------------------------------
     CONFIRMATION MODAL & TOASTS
     ------------------------------------------------------------------------ */
  setupModal() {
    const modal = document.getElementById('confirm-modal');
    const btnClose = document.getElementById('btn-modal-close');
    const btnCancel = document.getElementById('btn-modal-cancel');
    const btnConfirm = document.getElementById('btn-modal-confirm');

    const closeModal = () => {
      modal.classList.add('hidden');
      this.modalCallback = null;
    };

    if (btnClose) btnClose.addEventListener('click', closeModal);
    if (btnCancel) btnCancel.addEventListener('click', closeModal);

    if (btnConfirm) {
      btnConfirm.addEventListener('click', () => {
        if (typeof this.modalCallback === 'function') {
          this.modalCallback();
        }
        closeModal();
      });
    }
  },

  openConfirmModal(title, message, onConfirm) {
    const modal = document.getElementById('confirm-modal');
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').textContent = message;
    this.modalCallback = onConfirm;
    modal.classList.remove('hidden');
  },

  showToast(message, type = 'safe') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type === 'danger' ? 'toast-danger' : (type === 'warn' ? 'toast-warn' : 'toast-safe')}`;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => {
        if (toast.parentElement) toast.parentElement.removeChild(toast);
      }, 300);
    }, 3200);
  },

  escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
};

// Initialize Application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
