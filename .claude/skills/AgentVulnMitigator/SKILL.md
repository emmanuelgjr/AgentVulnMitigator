```markdown
# AgentVulnMitigator Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and conventions used in the AgentVulnMitigator Python codebase. You'll learn how to structure files, write imports/exports, follow commit message styles, and understand the project's approach to testing. This guide is ideal for contributors who want to maintain consistency and quality in their code.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `vulnerability_scanner.py`, `report_generator.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .utils import parse_config
    from .models import Vulnerability
    ```

### Export Style
- Use **named exports** (explicitly define what is exported from a module).
  - Example:
    ```python
    __all__ = ['scan_vulnerabilities', 'generate_report']
    ```

### Commit Messages
- Freeform style, no strict prefixes.
- Average commit message length: ~73 characters.
- Example:
  ```
  Add initial vulnerability scanning logic and config parser
  ```

## Workflows

### Project Setup
**Trigger:** When starting development or onboarding a new contributor  
**Command:** `/setup`

1. Clone the repository.
2. Set up a Python virtual environment.
3. Install dependencies (if a `requirements.txt` or `pyproject.toml` exists).
4. Verify the structure follows snake_case and relative import conventions.

### Adding a New Module
**Trigger:** When introducing new functionality  
**Command:** `/add-module`

1. Create a new Python file using snake_case (e.g., `new_feature.py`).
2. Use relative imports to access utilities or models.
3. Define `__all__` for explicit exports.
4. Write clear, descriptive commit messages.

### Reviewing Code for Style
**Trigger:** Before submitting a pull request  
**Command:** `/style-check`

1. Check that all files use snake_case naming.
2. Ensure all imports are relative within the package.
3. Confirm that modules use named exports via `__all__`.
4. Review commit messages for clarity and completeness.

## Testing Patterns

- The testing framework is **unknown**, but test files follow the `*.test.ts` pattern, suggesting some TypeScript-based tests may exist (possibly for frontend or integration testing).
- Python-specific test patterns are not detected.
- If adding tests, follow the existing naming convention and place tests in appropriately named files (e.g., `module_name.test.ts`).

## Commands
| Command      | Purpose                                         |
|--------------|-------------------------------------------------|
| /setup       | Set up the development environment              |
| /add-module  | Add a new Python module following conventions   |
| /style-check | Review code for style and commit message quality|
```
