# Pull Request Descriptions

PR descriptions use the repo templates in `.github/PULL_REQUEST_TEMPLATE/`. The template is the source of truth — match it exactly. For a feature branch merging into `master`, that is `feature_branch_pr_template.md`:

```markdown
### Motivation

<prose explaining why these changes are needed>

### Acceptance Criteria

- <one bullet per thing this PR delivers>

### Checklist

- [ ] If you are requesting a merge into `master`, confirm this code is production-ready and can be included in future releases as soon as it gets merged
```

## Rules

- Use only these three sections — `Motivation`, `Acceptance Criteria`, `Checklist` — in this order, and add no others (no `How it works`, `Scope`, `Validation`, `Notes`, etc.).
- Do not use `####` subsections. `Acceptance Criteria` is a single flat bullet list.
- `Motivation` is prose answering *why*; `Acceptance Criteria` is an imperative bullet list of *what* the PR does.
- For a stacked PR, add a single `Depends on #<number>` line at the very top, above `### Motivation`.
- Wrap code identifiers, paths, and literals in single backticks.
