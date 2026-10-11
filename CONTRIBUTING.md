# Contributing

Corrections and additions are welcome, especially to the law register, new lessons and new practice cases.

## Ground rules

- Every piece of content exists in Arabic and English. A pull request that adds one language only fails the tests.
- Arabic follows one rule: a period only closes a sentence. Join clauses with connectives such as و، ف، ثم،
  لأن، لذا، لكن، بل rather than commas, semicolons or colons. Labels carry no period. Write natural Arabic for
  the context, never a word for word translation.
- Every number in the English text must appear in the Arabic text. The tests compare them.
- No Unicode dashes. Use a comma, a full stop or the word you mean.
- Laws and standards need a source a reader can open. Mark anything you could not confirm in the caveat.
- Practice evidence must stay synthetic: `.example` domains and RFC 5737 addresses only.
- Generated files (`docs/data/bundle.json`, `docs/labs/`) are never edited by hand. Change the sources and run
  `python3 scripts/build_site.py`.

## Checks

```sh
python3 scripts/preflight.py
```

This rebuilds the site data, checks that generated files are current, runs the language checks, the Python
tests, the browser parity tests and, when Playwright is installed, the full browser test suite.
