import { patterns, AttackPattern } from "@/data/patterns";

type Match = AttackPattern;

export type DetectionResult = {
  riskLevel: string;
  score: number;
  matches: Match[];
  explanation: string;
  steps: string[];
  attackTypes: string[];
};

function normalize(text: string) {
  return text.toLowerCase();
}

export function analyzePrompt(input: string): DetectionResult {
  const lower = normalize(input);

  let matches: Match[] = [];
  let score = 0;
  let attackTypesSet = new Set<string>();

  patterns.forEach((p) => {
    const matched = p.keywords.every((word) =>
      lower.includes(normalize(word))
    );

    if (matched) {
      matches.push(p);
      score += p.risk;
      attackTypesSet.add(p.type);
    }
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
        ? "Detected patterns associated with prompt injection attacks including instruction override, prompt leaking, role manipulation, or indirect injection."
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