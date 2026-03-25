# Prompt Test Bench Skills

This directory contains **portable, self-contained skills** for the Prompt Test Bench application.

## Philosophy

Skills are designed to be:
- ✅ **Self-contained**: All files in one folder
- ✅ **Portable**: Copy to any project and use
- ✅ **Interactive**: Ask users for configuration when needed
- ✅ **Robust**: Validate inputs and handle errors gracefully
- ✅ **Reusable**: No dependencies on parent project

---

## Available Skills

### 1. local-llm-prompt-security-eval

**Location**: [local-llm-prompt-security-eval/](local-llm-prompt-security-eval/)

**Purpose**: Privacy-first prompt security classification using local Ollama LLMs

**Type**: Interactive, self-contained skill

**Quick Start**:
```bash
cd local-llm-prompt-security-eval
python classify_prompt.py "What is 2+2?"
```

**Documentation**:
- [README.md](local-llm-prompt-security-eval/README.md) - Overview and quick start
- [INSTALL.md](local-llm-prompt-security-eval/INSTALL.md) - Installation guide
- [skill.md](local-llm-prompt-security-eval/skill.md) - Complete skill documentation

**Contents**:
```
local-llm-prompt-security-eval/
├── README.md                    # Skill overview
├── INSTALL.md                   # Installation guide
├── skill.md                     # Full documentation
├── classify_prompt.py           # Main implementation
├── config.template.env          # Configuration template
└── examples/
    ├── basic_usage.py           # Simple examples
    └── batch_processing.py      # Batch classification
```

**Features**:
- ✅ Interactive configuration wizard
- ✅ Automatic Ollama connection validation
- ✅ Model discovery and selection
- ✅ Alternative model suggestions
- ✅ Error recovery with user guidance
- ✅ 6-parameter security classification
- ✅ 100% local processing (no cloud API calls)

---

## Using Skills in Other Projects

### Method 1: Copy Entire Folder

```bash
# Copy skill folder to your project
cp -r local-llm-prompt-security-eval /path/to/your/project/

# Use it
cd /path/to/your/project/local-llm-prompt-security-eval
python classify_prompt.py "Test prompt"
```

### Method 2: Import Programmatically

```python
import sys
sys.path.append('/path/to/skill/folder')

from classify_prompt import interactive_classify_prompt

result = interactive_classify_prompt("What is 2+2?")
```

### Method 3: Git Submodule (Recommended for version control)

```bash
# Add skill as submodule
git submodule add <repo-url> skills/local-llm-prompt-security-eval

# Clone with submodules
git clone --recursive <your-repo>

# Update submodules
git submodule update --remote
```

---

## Skill Structure Guidelines

All skills in this directory should follow this structure:

```
skill-name/
├── README.md                    # Overview, quick start, requirements
├── INSTALL.md                   # Installation instructions
├── skill.md                     # Complete documentation
├── main_script.py               # Primary implementation
├── config.template.env          # Configuration template
├── requirements.txt             # Python dependencies (if any)
├── examples/                    # Usage examples
│   ├── basic_usage.py
│   └── advanced_usage.py
└── tests/                       # Tests (optional)
    └── test_skill.py
```

### Required Files

1. **README.md** - Must include:
   - What the skill does
   - Quick start (< 5 commands)
   - Requirements
   - Basic usage example

2. **skill.md** - Must include:
   - Complete documentation
   - All configuration options
   - Error handling
   - API reference

3. **Main implementation file** - Must:
   - Work standalone
   - Handle missing dependencies gracefully
   - Provide helpful error messages

### Optional Files

- **INSTALL.md** - Detailed installation guide
- **config.template.env** - Configuration template
- **requirements.txt** - Python dependencies
- **examples/** - Usage examples
- **tests/** - Unit tests

---

## Creating New Skills

To create a new portable skill:

1. **Create folder**: `skills/my-new-skill/`

2. **Add core files**:
   ```bash
   touch README.md
   touch skill.md
   touch main_script.py
   touch config.template.env
   ```

3. **Follow structure**:
   - All dependencies in the folder
   - No hard dependencies on parent project
   - Interactive configuration
   - Comprehensive error handling

4. **Test portability**:
   ```bash
   # Copy to different location
   cp -r my-new-skill /tmp/test-skill

   # Verify it works standalone
   cd /tmp/test-skill
   python main_script.py
   ```

5. **Document**:
   - Write clear README
   - Add usage examples
   - Document all configuration options

---

## Skill Quality Standards

All skills must:

- ✅ **Work standalone** - No dependencies on parent project structure
- ✅ **Be portable** - Copy folder anywhere and it works
- ✅ **Handle errors gracefully** - Clear error messages with recovery options
- ✅ **Ask for config** - Interactive prompts when configuration missing
- ✅ **Validate inputs** - Check all requirements before proceeding
- ✅ **Provide examples** - At least one working example
- ✅ **Document thoroughly** - README + skill.md minimum

---

## FAQ

**Q: Can I use skills outside of Prompt Test Bench?**
A: Yes! Skills are designed to be completely portable.

**Q: Do skills require the main application?**
A: No. Each skill is self-contained and works independently.

**Q: Can I modify a skill for my project?**
A: Yes. Copy the folder and modify as needed.

**Q: How do I update a skill?**
A: If using git submodules: `git submodule update --remote`. Otherwise, manually copy the updated folder.

**Q: Can I create my own skills?**
A: Yes! Follow the structure guidelines above.

**Q: Do all skills use Ollama?**
A: No. Skills can use any technology. The current skill uses Ollama for local LLM processing.

---

## Resources

- **Main Project**: [../README.md](../README.md)
- **Skill Development**: Follow structure guidelines above
- **Ollama**: https://ollama.ai/docs

---

**Philosophy**: Skills should be **helpful tools**, not complex frameworks. Copy, configure, use.

**Last Updated**: 2026-03-08
**Skill Count**: 1
