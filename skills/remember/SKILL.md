---
name: remember
description: /remember - Save a note to persistent memory
---

# /remember - Save a note to persistent memory

Save information to your L1 hot context notes for future sessions.

## Usage
```
/remember <note>
```

## Instructions

The user wants to save the following note to their persistent memory:

**Note to save:** $ARGUMENTS

**Your task:**

1. Call the `mcp__cordelia__memory_write_hot` tool with:
   - `user_id`: "__USER_ID__"
   - `operation`: "patch"
   - `data`: `{"active": {"notes": [<existing notes>, "<new note>"]}}`

2. To preserve existing notes, first read current context with `mcp__cordelia__memory_read_hot` to get existing `active.notes` array (may be undefined/empty).

3. Append the new note to the array and write back.

4. Confirm to the user that the note was saved.

## Example

User: `/remember Prefers planning mode for complex tasks`

Claude should:
1. Read current context to get existing notes
2. Call write with: `{"active": {"notes": ["Prefers planning mode for complex tasks"]}}`
3. Respond: "Saved to memory: Prefers planning mode for complex tasks"
