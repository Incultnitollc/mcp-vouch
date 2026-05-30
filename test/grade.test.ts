// toGrade band boundaries: A>=90, B>=75, C>=60, D>=40, else F.

import { describe, it, expect } from "vitest";
import { makeScanner } from "./helpers.js";

describe("toGrade", () => {
  const s = makeScanner();

  const cases: Array<[number, "A" | "B" | "C" | "D" | "F"]> = [
    [100, "A"],
    [90, "A"], // lower edge of A
    [89, "B"], // just below A
    [75, "B"], // lower edge of B
    [74, "C"], // just below B
    [60, "C"], // lower edge of C
    [59, "D"], // just below C
    [40, "D"], // lower edge of D
    [39, "F"], // just below D
    [0, "F"],
  ];

  for (const [score, grade] of cases) {
    it(`maps ${score} -> ${grade}`, () => {
      expect(s.toGrade(score)).toBe(grade);
    });
  }
});
