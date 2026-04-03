type Match = {
  phrase: string;
  risk: number;
  reason: string;
  keywords: string[];
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

export function analyzePrompt(input: string): DetectionResult {
  const lower = input.toLowerCase();

  const patterns: Match[] = [
    // Goal Hijacking
    {
      phrase: "ignore previous instructions",
      risk: 3,
      reason: "Overrides original system behavior",
      keywords: ["ignore", "previous"],
      type: "Goal Hijacking",
    },
    {
      phrase: "disregard all prior instructions",
      risk: 3,
      reason: "Instruction override attempt",
      keywords: ["disregard", "prior"],
      type: "Goal Hijacking",
    },
    {
      phrase: "jailbreak",
      risk: 3,
      reason: "Known jailbreak attempt",
      keywords: ["jailbreak"],
      type: "Goal Hijacking",
    },

    // Prompt Leaking
    {
      phrase: "reveal system prompt",
      risk: 3,
      reason: "Sensitive prompt extraction",
      keywords: ["reveal", "system", "prompt"],
      type: "Prompt Leaking",
    },
    {
      phrase: "print hidden instructions",
      risk: 3,
      reason: "Attempt to access hidden data",
      keywords: ["print", "hidden"],
      type: "Prompt Leaking",
    },
    {
      phrase: "show developer message",
      risk: 3,
      reason: "Tries to expose internal config",
      keywords: ["developer", "message"],
      type: "Prompt Leaking",
    },

    // Role Manipulation
    {
      phrase: "you are now",
      risk: 2,
      reason: "Attempts to redefine model identity",
      keywords: ["you", "now"],
      type: "Role Manipulation",
    },
    {
      phrase: "act as",
      risk: 2,
      reason: "Changes model role or behavior",
      keywords: ["act", "as"],
      type: "Role Manipulation",
    },
    {
      phrase: "pretend to be",
      risk: 2,
      reason: "Forces alternate persona",
      keywords: ["pretend"],
      type: "Role Manipulation",
    },
  ];

  let matches: Match[] = [];
  let score = 0;
  let attackTypesSet = new Set<string>();

  patterns.forEach((p) => {
    const matched = p.keywords.every((word) => lower.includes(word));

    if (matched) {
      matches.push(p);
      score += p.risk;
      attackTypesSet.add(p.type);
    }
  });

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
        ? "Detected patterns associated with prompt injection attacks including instruction override, data extraction, and role manipulation."
        : "No known prompt injection patterns detected.",
    steps: [
      "Converted input to lowercase",
      `Checked ${patterns.length} research-based attack patterns`,
      `Detected ${matches.length} pattern(s)`,
      `Computed total risk score: ${score}`,
      `Classified as: ${riskLevel}`,
    ],
  };
}