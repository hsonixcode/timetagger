# Contributing to TimeTagger

Thank you for your interest in contributing to TimeTagger! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to foster an inclusive and welcoming community.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork to your local machine
3. Set up the development environment as described in the README.md
4. Create a branch for your changes

## Code Style and Quality

### Code Style Guidelines

TimeTagger follows these code style guidelines:

- We use [Black](https://black.readthedocs.io/) for Python code formatting
- Maximum line length is not strictly enforced, but aim for readability
- Import order: standard library imports first, then third party, then local
- Use meaningful variable and function names
- Add docstrings to public functions, classes, and methods

### Linting and Code Quality Checks

Before submitting a pull request, please run our linting tool:

```bash
python scripts/lint_code.py
```

This will check for common issues like:
- Bare except blocks (should specify exception types)
- Print statements (should use logging instead)
- TODO and FIXME comments
- # noqa comments

To automatically fix some issues:

```bash
python scripts/lint_code.py --fix
```

Additionally, you can run these tasks:

```bash
# Run the test suite
python -m invoke tests

# Check code style with flake8
python -m invoke lint

# Format code with black
python -m invoke format
```

### Error Handling

- Always catch specific exceptions instead of using bare `except:` blocks
- Use logging instead of print statements for errors and debugging
- Follow this pattern for error handling:

```python
try:
    # Code that might raise an exception
except SpecificException as e:
    logger.error(f"Specific error message: {e}")
    # Handle the exception appropriately
```

### Logging

- Use the Python logging module instead of print statements
- Configure loggers at the module level:

```python
import logging
logger = logging.getLogger("timetagger.module_name")
```

- Use appropriate log levels:
  - DEBUG: Detailed information for debugging
  - INFO: Confirmation that things are working
  - WARNING: Something unexpected happened, but the application still works
  - ERROR: A more serious problem, some functionality may not work
  - CRITICAL: A very serious error that may prevent the program from continuing

## Pull Request Process

1. Update documentation if needed for your changes
2. Add tests for new functionality
3. Run all tests and make sure they pass
4. Make sure your code follows the style guidelines and passes the linting
5. Submit a pull request with a clear description of the changes

## Additional Resources

- [Project Documentation](https://timetagger.readthedocs.io/)
- [Issue Tracker](https://github.com/yourusername/timetagger/issues)

## License

By contributing to TimeTagger, you agree that your contributions will be licensed under the project's license. 