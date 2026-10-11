# Security

Qassas is a teaching toolkit. It parses untrusted files, so parser bugs matter.

- The toolkit never executes content from evidence files and opens SQLite databases from a temporary copy in read only mode.
- The MCP server is read only and refuses any path outside the folder given with `--root`.
- The website runs every lab in the browser. Files you open are not uploaded anywhere.

Report a vulnerability privately through GitHub security advisories on this repository or by email to site@hotmail.com.
Please include a sample file that reproduces the problem.
