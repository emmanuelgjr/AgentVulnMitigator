# Examples

## `demo.py` — the 60-second attack/block walkthrough

```bash
python examples/demo.py
```

Runs seven canonical attacks (direct injection, zero-width injection,
confusable injection, spaced-letter injection, credit-card leak, XSS
payload, SSRF to cloud metadata) through `Guard.protect(...)` and prints
which ones get blocked.

## Recording the GIF for the README

Install [VHS](https://github.com/charmbracelet/vhs):
```bash
brew install vhs            # macOS
# or:  go install github.com/charmbracelet/vhs@latest
```

Then:
```bash
vhs examples/demo.tape
# writes examples/demo.gif
```

Drop the resulting GIF into the top of the README:
```markdown
![demo](examples/demo.gif)
```

## Asciinema fallback

If you'd rather record to an asciicast:
```bash
asciinema rec demo.cast -c "python examples/demo.py"
agg demo.cast examples/demo.gif
```
