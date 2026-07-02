# Submitting these pages to the LangChain docs site

The two `.mdx` files here follow the official templates in
[`langchain-ai/docs`](https://github.com/langchain-ai/docs)
(`src/oss/python/integrations/middleware/TEMPLATE.mdx` and
`src/oss/python/integrations/tools/TEMPLATE.mdx`).

Per LangChain's [publish guide](https://docs.langchain.com/oss/python/contributing/publish-langchain),
the integration package itself stays in this repo and on PyPI — the PR to
LangChain is **documentation only**.

## Steps

1. Make sure `qovaris` is live on PyPI first (the pages embed PyPI badges).
2. Fork `https://github.com/langchain-ai/docs` under your GitHub account and
   clone it.
3. Create a branch, then copy the pages in:
   - `qovaris-middleware.mdx` → `src/oss/python/integrations/middleware/qovaris.mdx`
   - `qovaris-tool.mdx`       → `src/oss/python/integrations/tools/qovaris.mdx`
4. Add both pages to the site navigation (`docs.json` in the repo root — search
   for how existing middleware/tools pages are registered and mirror that).
5. Run their local preview (see the repo README) and check both pages render:
   frontmatter present, code blocks runnable, Mintlify components valid.
6. Open the PR against `langchain-ai/docs` `main`. Note in the description that
   the package is published on PyPI as `qovaris` and links to
   https://github.com/qovaris-ai/qovaris-guard.

## Review checklist LangChain applies

- CI passes, no typos/grammar issues
- Frontmatter on every page
- Code examples run as written (ours run offline in embedded mode)
- Mintlify components used correctly
- If AI-assisted, comply with their acceptable-LLM-use policy (disclose in PR)
