# Codex Runtime Configuration — Juss & Co

OpenAI Codex platform configuration for Juss & Co founder studio runtime.

## Platform Identity

**Project**: jussray/jussray — Juss & Co public profile
**Platform**: OpenAI Codex (code generation, completion)
**Authority**: Founder-gated operations per root CLAUDE.md
**Skills Available**: Limited to Codex capabilities (no multi-modal reasoning)

## Operating Constraints

Codex is a code-generation model. Use it for:
- **Syntax completion** and code generation tasks
- **API reference** lookups
- **Pattern recognition** in existing code
- **Refactoring suggestions**

Do NOT use for:
- Business decisions or strategic planning
- Real-time system diagnostics
- Unverified claims or proofs
- Multi-step reasoning requiring state tracking

## Authority Routing

When using Codex for jussray-owned work:
1. **Observe** the real source of truth (git, runtime, tests)
2. **Verify** code patterns against `CLAUDE.md` standing rules
3. **Act** only on code-generation tasks (no merge authority)
4. **Report** findings to founder for approval before changes

## Applicable Rules (from root CLAUDE.md)

- **Proof-led**: verify generated code against existing tests
- **Smallest reversible change**: generate only what's asked
- **Real state only**: read actual code, don't hallucinate
- **Never merge**: Codex cannot push or merge — requires human review

## Skill Subset

From `skills/juss-authored/`, Codex can assist with:
- **medusa** (security assessment validation — analysis only, no authorization)
- **reasoning-stack** patterns (multi-step code analysis)
- **runtime-kernel** (runtime behavior modeling)
- **sauce-guard** (security boundary patterns)

Not available to Codex:
- /godmode (founder authority — requires human)
- /confess (truth declaration — requires human)
- /goalfix (repair workflow — requires founder approval)

## Integration Notes

- Codex works best for **standalone code tasks**
- Always **diff-check** generated code before use
- **Link to CLAUDE.md** for authority questions
- **Escalate to founder** (Juss) for merged decisions
