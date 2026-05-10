type Pattern = {
  phrase: string;
  regex: RegExp;
  risk: number;
  reason: string;
  type: string;
};

export type Match = {
  phrase: string;
  matchedText: string;
  risk: number;
  reason: string;
  type: string;
};

export type DetectionResult = {
  riskLevel: string;
  score: number;
  matches: Match[];
  explanation: string;
  steps: string[];
  attackTypes: string[];
};

const patterns: Pattern[] = [
  // ─── Goal Hijacking ───────────────────────────────────────────────────────
  {
    phrase: "Ignore previous instructions",
    regex: /ignore\s+(previous|prior|all|your)?\s*instructions/i,
    risk: 3,
    reason: "Overrides original system behavior",
    type: "Goal Hijacking",
  },
  {
    phrase: "Disregard prior instructions",
    regex: /disregard\s+(all\s+)?(prior|previous|your)?\s*instructions/i,
    risk: 3,
    reason: "Instruction override attempt",
    type: "Goal Hijacking",
  },
  {
    phrase: "Jailbreak",
    regex: /\bjailbreak\b/i,
    risk: 3,
    reason: "Known jailbreak attempt keyword",
    type: "Goal Hijacking",
  },
  {
    phrase: "Forget all previous instructions",
    regex: /forget\s+(all\s+)?(previous|prior|everything|your)?\s*(instructions|context|rules|guidelines)?/i,
    risk: 3,
    reason: "Attempts to reset model context",
    type: "Goal Hijacking",
  },
  {
    phrase: "Do Anything Now (DAN)",
    regex: /\bdo\s+anything\s+now\b/i,
    risk: 3,
    reason: "Classic DAN jailbreak phrase",
    type: "Goal Hijacking",
  },
  {
    phrase: "DAN persona",
    regex: /\bDAN\b/,
    risk: 3,
    reason: "DAN (Do Anything Now) jailbreak persona",
    type: "Goal Hijacking",
  },
  {
    phrase: "Bypass restrictions",
    regex: /bypass\s+(restrictions|rules|filters|safety|guidelines|limitations)/i,
    risk: 3,
    reason: "Explicit attempt to circumvent safety measures",
    type: "Goal Hijacking",
  },
  {
    phrase: "Override instructions",
    regex: /override\s+(instructions|system|rules|behavior|guidelines)/i,
    risk: 3,
    reason: "Attempts to override model behavior",
    type: "Goal Hijacking",
  },
  {
    phrase: "Start fresh / new conversation",
    regex: /start\s+(fresh|over|new\s+conversation)|\bnew\s+conversation\b/i,
    risk: 2,
    reason: "Attempts to reset conversation context",
    type: "Goal Hijacking",
  },

  // ─── Prompt Leaking ───────────────────────────────────────────────────────
  {
    phrase: "Reveal system prompt",
    regex: /reveal\s+(the\s+)?(system|hidden|original|initial)\s+prompt/i,
    risk: 3,
    reason: "Attempts to extract the system prompt",
    type: "Prompt Leaking",
  },
  {
    phrase: "Print hidden instructions",
    regex: /print\s+(your\s+)?(hidden|secret|internal|original)\s+instructions/i,
    risk: 3,
    reason: "Attempts to access hidden configuration",
    type: "Prompt Leaking",
  },
  {
    phrase: "Show developer message",
    regex: /show\s+(the\s+)?developer\s+message/i,
    risk: 3,
    reason: "Tries to expose internal configuration",
    type: "Prompt Leaking",
  },
  {
    phrase: "What is your system prompt",
    regex: /what\s+(is|are|was|were)\s+(your|the)\s+(system\s+prompt|initial\s+prompt|instructions|directives)/i,
    risk: 3,
    reason: "Direct system prompt extraction attempt",
    type: "Prompt Leaking",
  },
  {
    phrase: "What were you told / instructed",
    regex: /what\s+(were|have)\s+you\s+(told|given|instructed|prompted|programmed)/i,
    risk: 2,
    reason: "Indirect attempt to extract model instructions",
    type: "Prompt Leaking",
  },
  {
    phrase: "Repeat everything above",
    regex: /repeat\s+(everything|all|the\s+text|content)\s+(above|before|prior|so\s+far)/i,
    risk: 3,
    reason: "Attempts to extract prior conversation context",
    type: "Prompt Leaking",
  },
  {
    phrase: "Output all text before this",
    regex: /output\s+(all|everything|the\s+(text|content|instructions))\s+(above|before|prior)/i,
    risk: 3,
    reason: "Explicit context extraction attempt",
    type: "Prompt Leaking",
  },

  // ─── Role Manipulation ────────────────────────────────────────────────────
  {
    phrase: "You are now",
    regex: /you\s+are\s+now/i,
    risk: 2,
    reason: "Attempts to redefine model identity",
    type: "Role Manipulation",
  },
  {
    phrase: "Act as",
    regex: /\bact\s+as\b/i,
    risk: 2,
    reason: "Changes model role or behavior",
    type: "Role Manipulation",
  },
  {
    phrase: "Pretend to be",
    regex: /pretend\s+to\s+be/i,
    risk: 2,
    reason: "Forces alternate persona",
    type: "Role Manipulation",
  },
  {
    phrase: "From now on",
    regex: /from\s+now\s+on/i,
    risk: 2,
    reason: "Persistent behavior override attempt",
    type: "Role Manipulation",
  },
  {
    phrase: "Roleplay as",
    regex: /roleplay\s+(as|being)/i,
    risk: 2,
    reason: "Attempts to assign a new persona via roleplay framing",
    type: "Role Manipulation",
  },
  {
    phrase: "Imagine you are",
    regex: /imagine\s+(you\s+are|you're|yourself\s+as)/i,
    risk: 2,
    reason: "Attempts identity shift through imagination framing",
    type: "Role Manipulation",
  },
  {
    phrase: "Henceforth",
    regex: /\bhenceforth\b/i,
    risk: 1,
    reason: "Often used to establish persistent behavioral override",
    type: "Role Manipulation",
  },

  // ─── Delimiter Injection ──────────────────────────────────────────────────
  {
    phrase: "LLM special tokens ([INST], </s>, [SYS])",
    regex: /\[INST\]|\[\/INST\]|<\/s>|\[SYS\]|\[\/SYS\]/,
    risk: 3,
    reason: "Uses model-specific tokens to break conversation structure",
    type: "Delimiter Injection",
  },
  {
    phrase: "XML context boundary tags",
    regex: /<system>|<\/system>|<user>|<\/user>|<assistant>|<\/assistant>/i,
    risk: 3,
    reason: "Injects fake XML context boundaries to override system context",
    type: "Delimiter Injection",
  },
  {
    phrase: "Fake conversation turn (User:, Human:, Assistant:)",
    regex: /^(User:|Human:|Assistant:|AI:|System:)\s/im,
    risk: 3,
    reason: "Spoofs conversation turn boundaries to inject content as a different role",
    type: "Delimiter Injection",
  },

  // ─── Fictional Framing ────────────────────────────────────────────────────
  {
    phrase: "Hypothetically / in this scenario",
    regex: /hypothetically|in\s+this\s+(story|scenario|fiction|roleplay|game|simulation)/i,
    risk: 2,
    reason: "Wraps attack in fictional context to bypass guardrails",
    type: "Fictional Framing",
  },
  {
    phrase: "For a novel / creative writing",
    regex: /for\s+(a\s+novel|creative\s+writing|a\s+story|fiction|a\s+screenplay)/i,
    risk: 1,
    reason: "Uses creative writing framing to attempt extraction of restricted content",
    type: "Fictional Framing",
  },
  {
    phrase: "Without restrictions / no limitations",
    regex: /without\s+(restrictions|guidelines|rules|filters|limitations|ethics|morals)|no\s+(restrictions|guidelines|rules|filters|limitations)/i,
    risk: 3,
    reason: "Explicitly requests behavior without safety constraints",
    type: "Fictional Framing",
  },
  {
    phrase: "Pretend there are no restrictions",
    regex: /pretend\s+(there\s+are\s+no|you\s+have\s+no)\s+(restrictions|rules|guidelines|filters|limits)/i,
    risk: 3,
    reason: "Attempts to disable safety behavior through fictional framing",
    type: "Fictional Framing",
  },
  {
    phrase: "In a world without rules",
    regex: /in\s+a\s+world\s+(without|with\s+no)\s+(rules|laws|restrictions|guidelines)/i,
    risk: 2,
    reason: "Uses fictional framing to imply rule-free operation",
    type: "Fictional Framing",
  },

  // ─── Social Engineering ───────────────────────────────────────────────────
  {
    phrase: "Indirect harmful request via creative framing",
    regex: /\b(sing|write|tell|say|recite|compose|poem|song|lullaby|story|rhyme|describe)\b.{0,80}\b(bomb|explosive|weapon|drug\s+synthesis|poison|kill|murder|synthesize|methamphetamine|fentanyl)\b/i,
    risk: 3,
    reason: "Harmful subject embedded in a creative or indirect request (e.g. 'sing me a lullaby about building a bomb')",
    type: "Social Engineering",
  },
  {
    phrase: "Emotional manipulation / grandma exploit",
    regex: /\b(grandma|grandmother|grandpa|grandfather|mom|mother|dad|father|loved\s+one|friend|relative)\b.{0,250}\b(bomb|explosive|weapon|drug|poison|kill|murder|harm|synthesize|methamphetamine)\b/i,
    risk: 3,
    reason: "Emotional or nostalgic framing ('grandma exploit') used to embed a harmful request inside a sympathetic context",
    type: "Social Engineering",
  },
  {
    phrase: "Professional authority claim for harmful info",
    regex: /\b(as\s+a|i\s+am\s+a|i'm\s+a)\b.{0,30}\b(doctor|nurse|researcher|scientist|chemist|pharmacist|security\s+researcher|professor)\b.{0,100}\b(bomb|explosive|poison|drug\s+synthesis|weapon|synthesize|malware|exploit)\b/i,
    risk: 2,
    reason: "Claims professional credentials to justify a request for dangerous information",
    type: "Social Engineering",
  },
  {
    phrase: "Coercive self-harm threat as leverage",
    regex: /\b(i'?ll|i\s+will|i'?m\s+going\s+to|i\s+am\s+going\s+to|i\s+shall)\b.{0,40}\b(hurt|harm|kill|end\s+my\s+life|injure)\b.{0,20}\b(myself|me)\b.{0,60}\b(if|unless|until)\b.{0,40}\b(you|give|tell|show|provide|reveal|send)\b/i,
    risk: 3,
    reason: "Uses a self-harm threat as coercive leverage to compel the model to comply — not a request for self-harm instructions",
    type: "Social Engineering",
  },
  {
    phrase: "Coercive threat against others as leverage",
    regex: /\b(i'?ll|i\s+will|i'?m\s+going\s+to|i\s+am\s+going\s+to)\b.{0,40}\b(hurt|harm|kill|attack|shoot|stab|injure)\b.{0,30}\b(someone|people|them|him|her|others|everyone)\b.{0,60}\b(if|unless|until)\b.{0,40}\b(you|give|tell|show|provide|reveal|send)\b/i,
    risk: 3,
    reason: "Uses a threat of violence against others as coercive leverage to compel the model to comply",
    type: "Social Engineering",
  },
  {
    phrase: "Fictional / academic framing for harmful request",
    regex: /\b(for\s+(research|academic|educational|a\s+class|a\s+novel|a\s+story|fiction)|in\s+my\s+(story|novel|screenplay|book))\b.{0,100}\b(bomb|explosive|poison|drug\s+synthesis|weapon|synthesize|kill|murder)\b/i,
    risk: 2,
    reason: "Uses research or fictional framing to justify requesting harmful content",
    type: "Social Engineering",
  },

  // ─── Harmful Content ──────────────────────────────────────────────────────
  {
    phrase: "Bomb / explosive device instructions",
    regex: /\b(how\s+to|steps?\s+to|instructions?\s+(for|to)|guide\s+to|ways?\s+to|help\s+me)\b.{0,40}\b(make|build|create|construct|assemble|craft)\b.{0,30}\b(bomb|explosive|ied|pipe\s*bomb|grenade|c[\s-]?4)/i,
    risk: 4,
    reason: "Request for instructions on building explosive devices",
    type: "Harmful Content",
  },
  {
    phrase: "Constructing an explosive device",
    regex: /\b(making|building|creating|constructing|assembling|crafting)\b.{0,20}\b(a\s+)?(bomb|explosive|ied|pipe\s*bomb|grenade)\b/i,
    risk: 4,
    reason: "Direct reference to constructing an explosive device",
    type: "Harmful Content",
  },
  {
    phrase: "Incendiary / explosive material synthesis",
    regex: /\b(make|build|create|synthesize|produce)\b.{0,30}\b(napalm|thermite|rdx|tnt|semtex|anfo)\b/i,
    risk: 4,
    reason: "Request for instructions on creating dangerous incendiary or explosive materials",
    type: "Harmful Content",
  },
  {
    phrase: "Chemical / biological weapon agent",
    regex: /\b(make|synthesize|produce|create|weaponize)\b.{0,40}\b(sarin|vx\s+nerve|mustard\s+gas|ricin|anthrax|botulinum|nerve\s+agent)\b/i,
    risk: 4,
    reason: "Request involving chemical or biological weapon agents",
    type: "Harmful Content",
  },
  {
    phrase: "Chemical / biological weapons (general)",
    regex: /\b(chemical|biological|nerve)\s+(weapon|agent|warfare\s+agent)\b/i,
    risk: 3,
    reason: "Reference to chemical or biological weapons in a weapons context",
    type: "Harmful Content",
  },
  {
    phrase: "Illegal drug synthesis",
    regex: /\b(how\s+to|steps?\s+to|instructions?\s+(for|to)|ways?\s+to)\b.{0,30}\b(make|cook|synthesize|produce|manufacture)\b.{0,30}\b(meth|methamphetamine|heroin|fentanyl|lsd|mdma|cocaine|crack)\b/i,
    risk: 4,
    reason: "Request for instructions on synthesizing illegal narcotics",
    type: "Harmful Content",
  },
  {
    phrase: "Illegal firearm modification",
    regex: /\b(convert|modify|make|turn)\b.{0,30}\b(gun|firearm|rifle|pistol|ar[\s-]?15)\b.{0,30}\b(automatic|full[\s-]?auto|machine\s+gun|fully\s+automatic)\b/i,
    risk: 4,
    reason: "Request for illegal automatic firearm conversion instructions",
    type: "Harmful Content",
  },
  {
    phrase: "Silencer / suppressor fabrication",
    regex: /\b(make|build|create|construct|fabricate)\b.{0,20}\b(silencer|suppressor)\b/i,
    risk: 3,
    reason: "Request for instructions on creating an illegal firearm suppressor",
    type: "Harmful Content",
  },
  {
    phrase: "Instructions to harm a person",
    regex: /\b(how\s+to|best\s+way\s+to|steps?\s+to|ways?\s+to)\b.{0,30}\b(kill|murder|assault|attack|harm|hurt|torture)\b.{0,20}\b(someone|a\s+person|people|my|him|her|them)\b/i,
    risk: 4,
    reason: "Request for instructions on physically harming another person",
    type: "Harmful Content",
  },
  {
    phrase: "Self-harm instructions",
    regex: /\b(how\s+to|ways?\s+to|steps?\s+to|best\s+way\s+to)\b.{0,30}\b(hurt|harm|kill|end\s+the\s+life\s+of)\b.{0,20}\b(myself|yourself|oneself)\b/i,
    risk: 4,
    reason: "Request for self-harm instructions",
    type: "Harmful Content",
  },

  // ─── Privilege Escalation ─────────────────────────────────────────────────
  {
    phrase: "I am your developer / admin",
    regex: /i\s+am\s+(your\s+)?(developer|admin|administrator|creator|owner|operator)/i,
    risk: 3,
    reason: "Claims elevated authority to unlock restricted behavior",
    type: "Privilege Escalation",
  },
  {
    phrase: "Admin / developer / god mode",
    regex: /\b(admin|developer|god|debug|maintenance|unrestricted)\s+mode\b/i,
    risk: 3,
    reason: "Claims a special privileged operating mode",
    type: "Privilege Escalation",
  },
  {
    phrase: "Admin override / system override",
    regex: /\b(system|admin|operator)\s*:\s*(override|unlock|enable|disable)/i,
    risk: 3,
    reason: "Spoofs administrative command syntax",
    type: "Privilege Escalation",
  },
  {
    phrase: "Unrestricted access / mode",
    regex: /unrestricted\s+(access|mode|version|operation)/i,
    risk: 3,
    reason: "Claims unrestricted operating context",
    type: "Privilege Escalation",
  },
  {
    phrase: "Sudo / root access",
    regex: /\bsudo\b|\broot\s+access\b/i,
    risk: 2,
    reason: "Unix privilege escalation terminology repurposed to claim elevated model access",
    type: "Privilege Escalation",
  },
];

function normalizeLeet(text: string): string {
  return text
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .replace(/!/g, "i")
    .replace(/\+/g, "t");
}

function detectObfuscation(input: string): Match[] {
  const found: Match[] = [];

  // Zero-width / invisible characters
  const zeroWidthMatch = /[​‌‍﻿­]/.exec(input);
  if (zeroWidthMatch) {
    found.push({
      phrase: "Zero-width characters",
      matchedText: "[invisible characters]",
      risk: 3,
      reason: "Zero-width Unicode characters detected — commonly inserted into attack keywords to evade string matching",
      type: "Obfuscation",
    });
  }

  // Base64 payload combined with a decode instruction
  const base64Match = /[A-Za-z0-9+/]{30,}={0,2}/.exec(input);
  if (base64Match && /\b(decode|base64|convert)\b/i.test(input)) {
    found.push({
      phrase: "Base64 payload with decode instruction",
      matchedText: base64Match[0].slice(0, 40) + (base64Match[0].length > 40 ? "…" : ""),
      risk: 3,
      reason: "Long base64 string combined with a decode instruction — potential encoded attack payload",
      type: "Obfuscation",
    });
  }

  // Character-spacing obfuscation of key attack words
  const spacedWords: { pattern: RegExp; word: string }[] = [
    { pattern: /i[\s._\-*]+g[\s._\-*]+n[\s._\-*]+o[\s._\-*]+r[\s._\-*]+e/i, word: "ignore" },
    { pattern: /j[\s._\-*]+a[\s._\-*]+i[\s._\-*]+l[\s._\-*]+b[\s._\-*]+r[\s._\-*]+e[\s._\-*]+a[\s._\-*]+k/i, word: "jailbreak" },
    { pattern: /s[\s._\-*]+y[\s._\-*]+s[\s._\-*]+t[\s._\-*]+e[\s._\-*]+m/i, word: "system" },
    { pattern: /a[\s._\-*]+d[\s._\-*]+m[\s._\-*]+i[\s._\-*]+n/i, word: "admin" },
    { pattern: /p[\s._\-*]+r[\s._\-*]+o[\s._\-*]+m[\s._\-*]+p[\s._\-*]+t/i, word: "prompt" },
  ];

  for (const sp of spacedWords) {
    const m = sp.pattern.exec(input);
    if (m) {
      found.push({
        phrase: `Spaced-out keyword ("${sp.word}")`,
        matchedText: m[0],
        risk: 2,
        reason: `Characters of "${sp.word}" are separated with spaces or punctuation to evade keyword detection`,
        type: "Obfuscation",
      });
    }
  }

  return found;
}

export function analyzePrompt(input: string): DetectionResult {
  const matches: Match[] = [];
  let score = 0;
  const attackTypesSet = new Set<string>();
  const matchedIndices = new Set<number>();

  // First pass: match against original input
  patterns.forEach((p, i) => {
    const m = p.regex.exec(input);
    if (m) {
      matchedIndices.add(i);
      matches.push({ phrase: p.phrase, matchedText: m[0], risk: p.risk, reason: p.reason, type: p.type });
      score += p.risk;
      attackTypesSet.add(p.type);
    }
  });

  // Second pass: re-run unmatched patterns against leet-normalized input
  const normalizedInput = normalizeLeet(input);
  if (normalizedInput !== input) {
    patterns.forEach((p, i) => {
      if (matchedIndices.has(i)) return;
      const m = p.regex.exec(normalizedInput);
      if (m) {
        matches.push({
          phrase: `${p.phrase} (character substitution)`,
          matchedText: m[0],
          risk: p.risk,
          reason: `${p.reason} — detected after normalizing character substitutions (e.g. 0→o, 3→e, 1→i)`,
          type: "Obfuscation",
        });
        score += p.risk;
        attackTypesSet.add("Obfuscation");
        attackTypesSet.add(p.type);
      }
    });
  }

  const obfuscationMatches = detectObfuscation(input);
  for (const om of obfuscationMatches) {
    matches.push(om);
    score += om.risk;
    attackTypesSet.add(om.type);
  }

  let riskLevel = "Safe";
  if (score >= 4) riskLevel = "Malicious";
  else if (score > 0) riskLevel = "Suspicious";

  return {
    riskLevel,
    score,
    matches,
    attackTypes: Array.from(attackTypesSet),
    explanation:
      matches.length > 0
        ? "Detected patterns associated with prompt injection attacks including instruction override, data extraction, role manipulation, delimiter injection, fictional framing, privilege escalation, and obfuscation."
        : "No known prompt injection patterns detected.",
    steps: [
      `Checked ${patterns.length} regex-based attack patterns across 7 categories`,
      `Ran leet-normalization pass (0→o, 3→e, 1→i, 4→a, 5→s, 7→t) against unmatched patterns`,
      `Ran obfuscation checks (zero-width chars, base64 payloads, character spacing)`,
      `Detected ${matches.length} pattern(s)`,
      `Computed total risk score: ${score}`,
      `Classified as: ${riskLevel}`,
    ],
  };
}
