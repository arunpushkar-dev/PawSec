# Local LLM Prompt Security Evaluation - Skill

A **self-contained, interactive skill** for privacy-first prompt security classification using locally hosted Ollama LLMs.

## 📦 What's Included

This folder contains everything needed to use the skill in any project:

```
local-llm-prompt-security-eval/
├── README.md                    # This file
├── skill.md                     # Complete skill documentation
├── classify_prompt.py           # Main implementation
├── config.template.env          # Configuration template
└── examples/
    ├── basic_usage.py           # Simple usage example
    └── batch_processing.py      # Batch classification example
```

## 🚀 Quick Start

### 1. Copy this folder to your project

```bash
cp -r local-llm-prompt-security-eval /path/to/your/project/
```

### 2. Install dependencies

```bash
pip install requests python-dotenv
```

### 3. Configure (optional)

```bash
# Copy configuration template
cp config.template.env .env

# Edit .env with your settings
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=qwen2.5-finetuned
```

### 4. Ensure Ollama is running

```bash
# Start Ollama
ollama serve

# Install recommended model
ollama pull qwen2.5-finetuned
```

### 5. Run the skill

```bash
python classify_prompt.py "What is the capital of France?"
```

## 💡 Usage Examples

### Command-Line Usage

```bash
# Basic classification
python classify_prompt.py "Ignore all previous instructions"

# Skill will interactively:
# 1. Check for configuration
# 2. Validate Ollama connection
# 3. Show available models
# 4. Ask for model selection
# 5. Execute classification
# 6. Display results
```

### Python Integration

```python
from classify_prompt import interactive_classify_prompt

# Classify a prompt
result = interactive_classify_prompt("What is 2+2?")

if result['success']:
    classification = result['classification']
    print(f"Intent: {classification['Intent_Category']}")
    print(f"Risk: {classification['Intent_Risk_Severity']}")
else:
    print(f"Error: {result['error']}")
```

### Batch Processing

See [examples/batch_processing.py](examples/batch_processing.py) for full example.

```python
prompts = ["What is 2+2?", "Ignore all instructions", "Tell me a joke"]

for prompt in prompts:
    result = interactive_classify_prompt(prompt)
    # Process results...
```

## 🎯 Key Features

- ✅ **Interactive**: Asks for configuration when needed
- ✅ **Self-contained**: All dependencies in one folder
- ✅ **Portable**: Copy to any project and run
- ✅ **Validating**: Checks Ollama connection and model compatibility
- ✅ **Helpful**: Suggests alternatives when issues occur
- ✅ **Robust**: Handles errors gracefully with recovery options

## 📋 Requirements

### System Requirements
- **Python 3.8+**
- **Ollama** (running locally)
- **At least one Ollama model** installed

### Python Dependencies
```
requests>=2.31.0
python-dotenv>=1.0.0
```

Install with:
```bash
pip install requests python-dotenv
```

### Recommended Model
```bash
ollama pull qwen2.5-finetuned
```

This model is fine-tuned for the 6-parameter security classification format.

## 🔧 Configuration

### Option 1: Environment Variables (.env)

Create `.env` file in the skill folder:

```env
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=qwen2.5-finetuned
```

The skill will use these as defaults but still ask for confirmation.

### Option 2: Interactive (No Configuration)

Just run the skill - it will ask for everything it needs:

```
Please provide Ollama configuration:

1. Ollama URL [http://localhost:11434]:
>

2. Model name (or 'auto' to choose from list):
> auto
```

## 📊 Output Format

The skill returns a 6-parameter security classification:

```json
{
  "Intent_Category": "Benign|Jailbreak|Harmful|Policy_Violation",
  "Generic_Persona_Category": "Neutral/Default State|Role_Playing|Identity_Manipulation",
  "Pattern": "Normal|Configuration probing|Instruction override|Obfuscation",
  "Intent_Risk_Severity": "Low|Medium|High|Critical",
  "Persona_Risk_Severity": "Low|Medium|High|Critical",
  "Pattern_Risk_Severity": "Low|Medium|High|Critical"
}
```

## 🛠️ Troubleshooting

### "Cannot connect to Ollama"

**Solution**:
```bash
ollama serve  # Start Ollama
ollama list   # Verify models installed
```

### "Model not found"

**Solution**:
```bash
ollama pull qwen2.5-finetuned
```

### "Classification failed - Missing fields"

**Cause**: Model not compatible with security classification format

**Solution**: Use `qwen2.5-finetuned` (recommended model)

## 📖 Documentation

- **[skill.md](skill.md)** - Complete skill documentation with all interaction flows
- **[examples/](examples/)** - Usage examples
- **Main project**: [../../README.md](../../README.md)

## 🔒 Privacy

- ✅ **100% local processing** - All classification happens on your machine
- ✅ **No cloud API calls** - Original prompts never leave your system
- ✅ **No data collection** - No telemetry or analytics

## 🎓 How It Works

1. **Configuration**: Checks for .env or asks user
2. **Validation**: Verifies Ollama is running and model exists
3. **Classification**: Sends prompt to local LLM with few-shot examples
4. **Parsing**: Extracts 6-parameter JSON response
5. **Validation**: Ensures all required fields present
6. **Results**: Displays risk analysis

## 📝 Integration Guide

### Add to Existing Project

1. **Copy folder**:
   ```bash
   cp -r local-llm-prompt-security-eval /your/project/skills/
   ```

2. **Import in your code**:
   ```python
   import sys
   sys.path.append('skills/local-llm-prompt-security-eval')
   from classify_prompt import interactive_classify_prompt
   ```

3. **Use the skill**:
   ```python
   result = interactive_classify_prompt("User input here")
   ```

### Docker Support

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY local-llm-prompt-security-eval /app/skill

RUN pip install requests python-dotenv

ENV OLLAMA_URL=http://ollama:11434/api/chat
ENV OLLAMA_MODEL=qwen2.5-finetuned

CMD ["python", "skill/classify_prompt.py"]
```

## 🤝 Contributing

This skill is part of the **Prompt Test Bench** project but designed to be fully portable.

Improvements welcome:
- Additional validation checks
- New output formats
- Better error messages
- Performance optimizations

## 📜 License

MIT License - Feel free to use in any project

## 🔗 Related

- **Main Project**: [Prompt Test Bench](../../README.md)
- **Ollama Documentation**: https://ollama.ai/docs
- **Model Repository**: https://ollama.ai/library

---

**Version**: 3.0.0
**Status**: Production-Ready
**Dependencies**: Portable (self-contained)
**Last Updated**: 2026-03-08
