---
name: sprint
description: Show current sprint focus and next actions from Cordelia memory
---

# Sprint Status

Show the user's current sprint focus and next actions.

## Instructions

1. Call `mcp__cordelia__memory_read_hot` with user_id "__USER_ID__"
2. Display a concise summary:
   - Current sprint number and focus from `active.sprint` and `active.focus`
   - Next actions from `active.next`
   - Any blockers from `active.blockers`
   - Recent notes from `active.notes` (if relevant)

## Output Format

Keep it concise:

```
Sprint [N]: [focus]

Next:
- [action 1]
- [action 2]

[Blockers if any]
```
