# Guidelines for Claude Code

## Project Overview
Dragonfly is a bare metal management tool,
for everything from building machines to
reinstalling an entire datacentre.

## Rules
- **Consult README.md** for context whenever needed
- **Keep README.md Updated** - When adding new commands, features, or changing functionality, ALWAYS update the README.md Usage section. Palace uses the README to understand what exists, so outdated docs lead to duplicate suggestions!
- **Test Driven Development** - Write tests before implementing ANY code or feature, no matter how small. We aim for high code coverage from the beginning.
- **Zero Placeholders** - Do not put in references to commands or functionality that are not implemented yet or do not exist
- **Modularity** - Break down components into small, focused files (typically <200 LoC per file)
- **Test Modularity** - Tests should be modular and organized for easy understanding and maintenance
- **"DO NOT SIMPLIFY - EVER"** - When thinking of simplifying something, think through the change deeply and ask the user what they want to do
- **Commit Regularly** - Test after every change and commit very regularly with tiny atomic chunks
- **Follow Language Style Guides** - Adhere to the style guide of your primary language
- **Use Palace Tools** - Use `pal test`, `pal build`, `pal run` for development workflows

## Quality Standards
- Write comprehensive tests for all new features
- Keep functions small and focused
- Use meaningful variable and function names
- Document complex logic with clear comments
- Handle errors gracefully with proper error messages

## Development Workflow
1. **Understand Requirements** - Read README.md and existing code
2. **Write Tests First** - Create failing tests that define expected behavior
3. **Implement Features** - Write minimal code to make tests pass
4. **Refactor** - Clean up code while keeping tests green
5. **Commit** - Small, atomic commits with clear messages
