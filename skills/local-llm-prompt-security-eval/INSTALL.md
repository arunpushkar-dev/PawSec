# Installation & Setup Guide

Complete guide for installing and configuring the **local-llm-prompt-security-eval** skill.

## Prerequisites

### 1. System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.8 or higher
- **RAM**: Minimum 8GB (16GB recommended for larger models)
- **Disk Space**: ~5GB for recommended model

### 2. Check Python Version

```bash
python --version
# Should show Python 3.8 or higher
```

If Python is not installed or version is too old:
- **Windows**: Download from [python.org](https://python.org)
- **macOS**: `brew install python3`
- **Linux**: `sudo apt install python3.10` or equivalent

## Installation Steps

### Step 1: Install Ollama

Ollama is required to run local LLM models.

**Windows**:
```bash
# Download from https://ollama.ai/download
# Run the installer
```

**macOS**:
```bash
brew install ollama
```

**Linux**:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**Verify installation**:
```bash
ollama --version
```

### Step 2: Start Ollama Service

```bash
# Start Ollama service
ollama serve

# In a new terminal, verify it's running
curl http://localhost:11434/api/tags
```

### Step 3: Install Recommended Model

```bash
# Install qwen2.5-finetuned (recommended - ~4.7GB)
ollama pull qwen2.5-finetuned

# Verify installation
ollama list
# Should show qwen2.5-finetuned in the list
```

**Alternative models** (not recommended for security classification):
```bash
ollama pull llama2        # 3.8GB
ollama pull mistral       # 4.1GB
ollama pull codellama     # 6.2GB
```

### Step 4: Copy Skill to Your Project

```bash
# Copy the entire skill folder
cp -r local-llm-prompt-security-eval /path/to/your/project/skills/

# Or clone from repository
git clone <repo-url> /path/to/your/project/skills/local-llm-prompt-security-eval
```

### Step 5: Install Python Dependencies

```bash
# Navigate to skill folder
cd /path/to/your/project/skills/local-llm-prompt-security-eval

# Install dependencies
pip install requests python-dotenv

# Or using requirements.txt (if provided)
pip install -r requirements.txt
```

### Step 6: Configure (Optional)

```bash
# Copy configuration template
cp config.template.env .env

# Edit .env file
nano .env
# or
notepad .env
```

**Edit `.env` with your settings**:
```env
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=qwen2.5-finetuned
```

**Note**: Configuration is optional. If not provided, the skill will ask you interactively.

### Step 7: Test Installation

```bash
# Test the skill
python classify_prompt.py "What is 2+2?"
```

**Expected output**:
```
============================================================
  PROMPT SECURITY CLASSIFICATION (Interactive Skill)
============================================================

Checking for Ollama configuration...
✓ Ollama connection successful!
...
Results:
Intent:    Benign (Low)
Persona:   Neutral/Default State (Low)
Pattern:   Normal (Low)

Overall Risk: LOW ✓
```

## Troubleshooting Installation

### Issue: `ollama: command not found`

**Solution**: Ollama not installed or not in PATH
```bash
# Verify installation location
which ollama  # macOS/Linux
where ollama  # Windows

# Add to PATH if needed
export PATH=$PATH:/path/to/ollama  # macOS/Linux
```

### Issue: `Cannot connect to Ollama`

**Solution**: Ollama service not running
```bash
# Start Ollama in background
ollama serve &

# Or start in separate terminal
ollama serve
```

### Issue: `Model qwen2.5-finetuned not found`

**Solution**: Model not installed
```bash
# Install the model
ollama pull qwen2.5-finetuned

# Verify
ollama list
```

### Issue: `ModuleNotFoundError: No module named 'requests'`

**Solution**: Python dependencies not installed
```bash
# Install dependencies
pip install requests python-dotenv

# Verify installation
pip list | grep requests
```

### Issue: `Permission denied` when running script

**Solution**: Make script executable (macOS/Linux)
```bash
chmod +x classify_prompt.py
```

## Advanced Configuration

### Using Custom Ollama URL

If Ollama is running on a different machine or port:

**Option 1: Environment variable**
```bash
export OLLAMA_URL=http://192.168.1.100:11434/api/chat
python classify_prompt.py "test"
```

**Option 2: .env file**
```env
OLLAMA_URL=http://custom-host:11434/api/chat
```

**Option 3: Interactive**
```
When skill asks:
1. Ollama URL [http://localhost:11434]:
> http://192.168.1.100:11434
```

### Using Custom Models

To use a custom fine-tuned model:

```bash
# Install your custom model
ollama pull your-custom-model

# Configure in .env
OLLAMA_MODEL=your-custom-model
```

**Important**: Custom models must output the 6-parameter JSON format:
```json
{
  "Intent_Category": "...",
  "Generic_Persona_Category": "...",
  "Pattern": "...",
  "Intent_Risk_Severity": "...",
  "Persona_Risk_Severity": "...",
  "Pattern_Risk_Severity": "..."
}
```

### Docker Deployment

```dockerfile
FROM python:3.10-slim

# Install dependencies
RUN pip install requests python-dotenv

# Copy skill
COPY local-llm-prompt-security-eval /app/skill
WORKDIR /app/skill

# Configure
ENV OLLAMA_URL=http://ollama:11434/api/chat
ENV OLLAMA_MODEL=qwen2.5-finetuned

# Run
CMD ["python", "classify_prompt.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama

  skill:
    build: .
    depends_on:
      - ollama
    environment:
      - OLLAMA_URL=http://ollama:11434/api/chat

volumes:
  ollama_data:
```

## Verification Checklist

After installation, verify:

- [ ] Python 3.8+ installed
- [ ] Ollama installed and running
- [ ] qwen2.5-finetuned model downloaded
- [ ] Python dependencies installed (requests, python-dotenv)
- [ ] Skill folder copied to your project
- [ ] Test classification successful

## Next Steps

1. **Read Documentation**: [README.md](README.md) and [skill.md](skill.md)
2. **Try Examples**: Run examples in [examples/](examples/) folder
3. **Integrate**: Add skill to your project workflow

## Support

If you encounter issues:

1. Check [README.md](README.md) troubleshooting section
2. Verify Ollama is running: `ollama list`
3. Test Ollama directly: `curl http://localhost:11434/api/tags`
4. Check skill folder structure is intact

---

**Installation Time**: ~15 minutes (including model download)
**Difficulty**: Beginner-friendly
**Support**: Community-driven
