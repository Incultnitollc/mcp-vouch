// Tests for the worker's container memory watchdog. The pure parsing + tree
// functions take injectable inputs so we never touch the real cgroup / /proc.

import { describe, expect, it, vi } from "vitest";
import {
  MemoryExceededError,
  MemoryWatchdog,
  descendantPids,
  parseCgroupMemoryBytes,
  parseProcStat,
  parseStatmResidentBytes,
  readContainerMemoryBytes,
} from "../src/worker/memory-guard.js";

describe("parseCgroupMemoryBytes", () => {
  it("parses a byte count", () => {
    expect(parseCgroupMemoryBytes("123456\n")).toBe(123456);
  });

  it("returns null for the unlimited sentinel 'max'", () => {
    expect(parseCgroupMemoryBytes("max\n")).toBeNull();
  });

  it("returns null for empty / null / garbage", () => {
    expect(parseCgroupMemoryBytes("")).toBeNull();
    expect(parseCgroupMemoryBytes(null)).toBeNull();
    expect(parseCgroupMemoryBytes("not-a-number")).toBeNull();
  });
});

describe("readContainerMemoryBytes", () => {
  it("prefers cgroup v2 (memory.current)", () => {
    const read = (p: string) => (p.endsWith("memory.current") ? "200\n" : null);
    expect(readContainerMemoryBytes(read)).toBe(200);
  });

  it("falls back to cgroup v1 (memory.usage_in_bytes) when v2 absent", () => {
    const read = (p: string) => (p.endsWith("memory.usage_in_bytes") ? "300\n" : null);
    expect(readContainerMemoryBytes(read)).toBe(300);
  });

  it("returns null when no cgroup accounting is readable (non-Linux dev box)", () => {
    expect(readContainerMemoryBytes(() => null)).toBeNull();
  });
});

describe("parseProcStat", () => {
  it("extracts pid and ppid from a normal stat line", () => {
    expect(parseProcStat("1234 (node) S 1000 1234 1234 0 -1")).toEqual({ pid: 1234, ppid: 1000 });
  });

  it("handles a comm containing spaces and a close paren", () => {
    // comm = "weird ) name" — ppid must still be read from after the LAST ')'.
    expect(parseProcStat("42 (weird ) name) R 7 42")).toEqual({ pid: 42, ppid: 7 });
  });

  it("returns null for an unparseable line", () => {
    expect(parseProcStat("garbage")).toBeNull();
  });
});

describe("descendantPids", () => {
  const snapshot = [
    { pid: 1, ppid: 0 }, // worker
    { pid: 2, ppid: 1 }, // npx
    { pid: 3, ppid: 2 }, // npm
    { pid: 4, ppid: 3 }, // node-gyp (grandchild)
    { pid: 5, ppid: 1 }, // sibling helper
    { pid: 9, ppid: 99 }, // unrelated tree
  ];

  it("collects the whole subtree, excluding the root itself", () => {
    expect(descendantPids(1, snapshot).sort((a, b) => a - b)).toEqual([2, 3, 4, 5]);
  });

  it("returns [] for a leaf with no children", () => {
    expect(descendantPids(4, snapshot)).toEqual([]);
  });
});

describe("parseStatmResidentBytes", () => {
  it("returns resident pages × page size (field 2)", () => {
    // statm: size resident shared text lib data dt — resident=100 pages × 4096.
    expect(parseStatmResidentBytes("2000 100 50 1 0 300 0")).toBe(100 * 4096);
  });

  it("returns null for an unparseable body", () => {
    expect(parseStatmResidentBytes("")).toBeNull();
  });
});

describe("MemoryWatchdog", () => {
  it("fires onExceed once when the sampled value crosses the limit", () => {
    vi.useFakeTimers();
    try {
      let used = 100 * 1024 * 1024;
      const sample = () => used;
      const wd = new MemoryWatchdog(400 * 1024 * 1024, 200, sample);
      const onExceed = vi.fn();
      wd.start(onExceed);

      vi.advanceTimersByTime(200); // 100Mi — under
      expect(onExceed).not.toHaveBeenCalled();

      used = 450 * 1024 * 1024; // now over the 400Mi limit
      vi.advanceTimersByTime(200);
      vi.advanceTimersByTime(200); // would fire again, but it stopped after first
      expect(onExceed).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("never fires when no memory signal is available (sampler returns null)", () => {
    vi.useFakeTimers();
    try {
      const wd = new MemoryWatchdog(1, 100, () => null);
      const onExceed = vi.fn();
      wd.start(onExceed);
      vi.advanceTimersByTime(1000);
      wd.stop();
      expect(onExceed).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("MemoryExceededError", () => {
  it("reports used and limit in Mi", () => {
    const err = new MemoryExceededError(450 * 1024 * 1024, 400 * 1024 * 1024);
    expect(err.name).toBe("MemoryExceededError");
    expect(err.message).toContain("450Mi");
    expect(err.message).toContain("400Mi");
  });
});
