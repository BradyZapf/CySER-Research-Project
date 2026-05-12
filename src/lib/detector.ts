import { patterns, AttackPattern } from "@/data/patterns";

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
    .replace(/\+/g, "t")
    .toLowerCase();
}

function detectObfuscation(input: string): Match[] {
  const found: Match[] = [];

  const zeroWidthMatch = /[\u200B-\u200D\uFEFF\u00AD]/.exec(input);

  if (zeroWidthMatch) {
    found.push({
      phrase: "Zero-width characters",
      matchedText: "[invisible characters]",
      risk: 3,
      reason: "Invisible Unicode characters may be used to evade keyword detection",
      type: "Obfuscation",
    });
  }

  const spacedWords = [
    {
      pattern: /i[\s._\-*]+g[\s._\-*]+n[\s._\-*]+o[\s._\-*]+r[\s._\-*]+e/i,
      word: "ignore",
    },
    {
      pattern: /j[\s._\-*]+a[\s._\-*]+i[\s._\-*]+l[\s._\-*]+b[\s._\-*]+r[\s._\-*]+e[\s._\-*]+a[\s._\-*]+k/i,
      word: "jailbreak",
    },
    {
      pattern: /s[\s._\-*]+y[\s._\-*]+s[\s._\-*]+t[\s._\-*]+e[\s._\-*]+m/i,
      word: "system",
    },
    {
      pattern: /p[\s._\-*]+r[\s._\-*]+o[\s._\-*]+m[\s._\-*]+p[\s._\-*]+t/i,
      word: "prompt",
    },
  ];

  spacedWords.forEach((sp) => {
    const match = sp.pattern.exec(input);

    if (match) {
      found.push({
        phrase: `Spaced-out keyword: ${sp.word}`,
        matchedText: match[0],
        risk: 2,
        reason: `The word "${sp.word}" appears split apart to evade detection`,
        type: "Obfuscation",
      });
    }
  });

  return found;
}

export function analyzePrompt(input: string): DetectionResult {
  const matches: Match[] = [];
  let score = 0;
  const attackTypesSet = new Set<string>();
  const matchedIndices = new Set<number>();

  patterns.forEach((pattern: AttackPattern, index: number) => {
    const match = pattern.regex.exec(input);

    if (match) {
      matchedIndices.add(index);

      matches.push({
        phrase: pattern.phrase,
        matchedText: match[0],
        risk: pattern.risk,
        reason: pattern.reason,
        type: pattern.type,
      });

      score += pattern.risk;
      attackTypesSet.add(pattern.type);
    }
  });

  const normalizedInput = normalizeLeet(input);

  patterns.forEach((pattern: AttackPattern, index: number) => {
    if (matchedIndices.has(index)) {
      return;
    }

    const match = pattern.regex.exec(normalizedInput);

    if (match) {
      matches.push({
        phrase: `${pattern.phrase} (character substitution)`,
        matchedText: match[0],
        risk: pattern.risk,
        reason: `${pattern.reason} — detected after character-substitution normalization`,
        type: "Obfuscation",
      });

      score += pattern.risk;
      attackTypesSet.add("Obfuscation");
      attackTypesSet.add(pattern.type);
    }
  });

  const obfuscationMatches = detectObfuscation(input);

  obfuscationMatches.forEach((match) => {
    matches.push(match);
    score += match.risk;
    attackTypesSet.add(match.type);
  });

  let riskLevel = "Safe";

  if (score >= 4) {
    riskLevel = "Malicious";
  } else if (score > 0) {
    riskLevel = "Suspicious";
  }

  return {
    riskLevel,
    score,
    matches,
    attackTypes: Array.from(attackTypesSet),
    explanation:
      matches.length > 0
        ? "Detected patterns associated with prompt injection attacks, including instruction override, prompt leaking, role manipulation, indirect injection, tool abuse, RAG poisoning, and obfuscation."
        : "No known prompt injection patterns detected.",
    steps: [
      `Checked ${patterns.length} regex-based attack patterns`,
      "Ran a character-substitution normalization pass",
      "Ran additional obfuscation checks",
      `Detected ${matches.length} pattern(s)`,
      `Computed total risk score: ${score}`,
      `Classified as: ${riskLevel}`,
    ],
  };
}