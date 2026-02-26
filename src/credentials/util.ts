// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Shared utility helpers for the credentials subsystem.
 */

/**
 * Generate a random UUID v4.
 * Uses the Web Crypto API when available; falls back to a
 * pure JS implementation for environments that lack it.
 */
export function randomUUID(): string {
  if (
    typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
  ) {
    return crypto.randomUUID();
  }

  // Fallback: manually assemble a UUID v4 from random bytes.
  const bytes = new Uint8Array(16);

  if (
    typeof crypto !== "undefined" &&
    typeof crypto.getRandomValues === "function"
  ) {
    crypto.getRandomValues(bytes);
  } else {
    // Last resort for environments without any Web Crypto support.
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }

  // Set UUID version (4) and variant bits.
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;

  const hexParts = Array.from(bytes).map((byte) =>
    byte.toString(16).padStart(2, "0")
  );

  return [
    hexParts.slice(0, 4).join(""),
    hexParts.slice(4, 6).join(""),
    hexParts.slice(6, 8).join(""),
    hexParts.slice(8, 10).join(""),
    hexParts.slice(10).join(""),
  ].join("-");
}

/**
 * Convert a `Date` or ISO-8601 string to a Unix timestamp (seconds).
 */
export function toUnixSeconds(date: Date | string): number {
  const d = typeof date === "string" ? new Date(date) : date;
  return Math.floor(d.getTime() / 1_000);
}

/**
 * Decode a base64url string to a `Uint8Array` without using Node.js Buffer.
 */
export function base64urlDecode(input: string): Uint8Array {
  // Restore standard base64 padding.
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const withPadding = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  const binaryString = atob(withPadding);
  const bytes = new Uint8Array(binaryString.length);
  for (let index = 0; index < binaryString.length; index++) {
    bytes[index] = binaryString.charCodeAt(index);
  }
  return bytes;
}
