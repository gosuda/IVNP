---
name: zero-slop
description: Enforces a strict Zero-Slop Policy across code comments, documentation, and Git commit messages, eliminating low-density filler, prompt regurgitation, and mechanical restatements.
license: MIT
---

# Zero-Slop Policy

## 1. Zero-Slop Policy (Core Philosophy)

We maintain a strict **Zero-Slop Policy** across all code comments, documentation, and Git commit messages.
"Slop" refers to low-density text, filler words, prompt regurgitation, internal monologue residue, or stating the obvious. Every piece of text committed to this repository must deliver high informational density for human maintainers. If text provides no non-obvious value, **omit it entirely**.

---

## 2. Code Comment Standards

### 🚫 Prohibited Comment Patterns (Slop)

1. **Prompt Paraphrasing**: Never rephrase user instructions or task requirements as code comments.
2. **Obvious Restatements**: Never describe what standard language syntax already makes clear (e.g., `// check if user exists`).
3. **Clumped / Misplaced Headers**: Do not dump 20+ lines of overview at file or function headers. Keep brief notes directly adjacent to the relevant logic.
4. **Historical Rants**: Do not document why deprecated code failed. Document only **what** the current code does and **why** this implementation was chosen.
5. **Reasoning / Monologue Residue**: Never leak internal chain-of-thought, planning notes, or self-dialogue into comments.

### ✅ When Comments Are Required

- **Non-obvious "Why"**: Business rules, hardware/browser quirks, upstream API bugs, security constraints, performance tradeoffs.
- **Complex Edge Cases**: Subtle race conditions, intricate regex patterns, bitwise calculations.

### Examples: Bad vs. Good

```typescript
// ❌ BAD (SLOP): Restating obvious interface fields and echoing prompt goals
/**
 * UserProfileData interface representing the profile information.
 * Created to handle user profile response properly so frontend can render.
 */
interface UserProfileData {
  id: string;
  email: string;
}

// ❌ BAD (SLOP): Restating clear syntax mechanics
// Checking if token is expired and throwing error if true
if (Date.now() > token.expiresAt) {
  throw new UnauthorizedError();
}

// ✅ GOOD (ZERO SLOP): Code is self-explanatory. No comment needed.
interface UserProfileData {
  id: string;
  email: string;
}

// ✅ GOOD (ZERO SLOP): Explains a subtle upstream quirk right at the call site
// Upstream auth server emits timestamps in seconds; Date.now() uses milliseconds.
if (Date.now() > token.expiresAt * 1000) {
  throw new UnauthorizedError();
}
```

---

## 3. Git Commit Message Standards

Commit messages must be concise, factual, and strictly focused on technical intent and consequences.

### 🚫 Prohibited Commit Patterns (Slop)

1. **Prompt Echoing**: Do not write `fix: implement user request to add pagination to table`.
2. **AI Fluff & Conversational Filler**: Never include phrases like `Updated files as requested`, `Refactored for better synergy`, or `Fixed bug according to feedback`.
3. **Mechanical File Audits**: Do not list every touched file when `git diff --stat` already provides this.
4. **Multi-Paragraph Narratives**: Do not write essays explaining basic language mechanics or general workflows.

### ✅ Commit Rules & Structure

- **Format**: Conventional Commits (`feat:`, `fix:`, `refactor:`, `perf:`, `chore:`, `test:`).
- **Subject Line**: Imperative mood, present tense, maximum 50–72 characters, no trailing period.
- **Body (Optional)**: Include only when necessary to explain **root causes**, **tradeoffs**, or **breaking changes**. Limit to 1–3 dense, factual bullet points.

### Examples: Bad vs. Good

```text
❌ BAD (SLOP):
commit 4a8b1c2
Author: AI Agent
Date:   ...

    feat: implemented the requested user authentication changes and token validation

    In this commit, we updated the authentication middleware because the user requested
    that expired tokens should throw an UnauthorizedError. We also cleaned up the imports
    and refactored some variable names across three files to make the codebase cleaner.

---

✅ GOOD (ZERO SLOP):
commit 4a8b1c2
Author: Engineer
Date:   ...

    fix(auth): handle second-based expiry timestamps from upstream auth service

    Upstream token payloads return `expiresAt` in seconds instead of milliseconds,
    causing immediate unauthorized errors on valid tokens.
```

---

## 4. Review Protocol: Handling "slop"

If a human reviewer comments **`"slop"`** on code, comments, or a commit message:

1. **For Comments**:
   - **Delete first**: If removing the comment leaves the code fully understandable, delete it.
   - **Relocate & Compress**: If context is critical, move it to the exact line and cut text length by at least 70%.
2. **For Commit Messages**:
   - Rewrite the subject and body to state strictly the technical root cause and fix. Strip all narrative padding.
3. **No Conversational Defense**: Do not justify or apologize in the chat interface. Apply the fix directly in the diff.
