---
name: persist
description: Analyze recent conversation for novelty and persist high-value content to Cordelia memory
---

# Persist to Memory

Analyze the recent conversation and persist high-novelty content to Cordelia L1 hot context.

## Instructions

1. Review the recent conversation (last 5-10 exchanges)

2. Identify high-novelty content using these signals:
   - **correction**: User corrected an assumption
   - **preference**: User expressed a preference or working style
   - **entity_new**: New person, project, or concept introduced
   - **decision**: A decision was made
   - **insight**: Pattern recognition, realization, learning
   - **blocker**: Blocker identified or resolved
   - **reference**: New key reference (book, person, concept)
   - **working_pattern**: How we work together
   - **meta_learning**: Insight about the collaboration itself

3. Skip low-novelty content:
   - Acknowledgments ("ok", "got it", "thanks")
   - Task mechanics ("read this file", "run that command")
   - Restating known context
   - Transient debugging/exploration

4. For each high-novelty item, determine the target:
   - `identity.key_refs` - foundational references
   - `active.notes` - insights, learnings, patterns
   - `active.blockers` - current blockers
   - `active.next` - next actions
   - `prefs` - preferences

5. Use `mcp__cordelia__memory_write_hot` with user_id "__USER_ID__" to persist, using patch operation

6. Report what was persisted in a concise summary

## Output Format

```
Persisted to memory:
- [signal] content -> target
- [signal] content -> target

Skipped (low novelty): N items
```
