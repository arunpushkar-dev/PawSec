# Skill: local-llm-prompt-security-eval

## Purpose
Analyze user prompts for security risks using locally hosted Ollama LLM, providing privacy-first security classification without sending data to cloud APIs. This skill is **fully interactive** and handles all configuration and validation autonomously.

## Trigger Phrases
- "classify prompt: [prompt text]"
- "analyze this prompt: [prompt text]"
- "check prompt security: [prompt text]"
- "evaluate prompt risk: [prompt text]"
- "security analysis: [prompt text]"

## Skill Behavior

When invoked, this skill will:
1. ✅ Ask user for Ollama configuration (URL, model)
2. ✅ Validate inputs (check if Ollama is running, model exists)
3. ✅ Suggest alternative models if requested model unavailable
4. ✅ Execute classification
5. ✅ Return 6-parameter security analysis

The skill is **completely self-contained** and does not require any UI configuration.

---

## Interactive Configuration Flow

### Phase 1: Configuration Gathering

**Step 1: Check for existing configuration**

```
Checking for Ollama configuration...

Found .env file with:
- OLLAMA_URL: http://localhost:11434/api/chat
- OLLAMA_MODEL: qwen2.5-finetuned

Would you like to:
A) Use these settings
B) Specify different configuration
C) Auto-detect from running Ollama

Your choice:
```

**Step 2: If user selects "B" or "C", ask for details**

```
Please provide Ollama configuration:

1. Ollama URL (default: http://localhost:11434):
   >

2. Preferred model (or 'auto' to see available models):
   >
```

**Step 3: Validate configuration**

### Phase 2: Validation & Model Discovery

**Step 1: Check Ollama connection**

```python
def verify_ollama_connection(ollama_url):
    """Verify Ollama is running and accessible"""
    try:
        base_url = ollama_url.replace('/api/chat', '')
        response = requests.get(f"{base_url}/api/tags", timeout=5)

        if response.status_code == 200:
            return {
                "success": True,
                "models": response.json().get('models', [])
            }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": "Cannot connect to Ollama. Is it running?"
        }
```

**Output to user:**
```
✓ Ollama connection successful!

Available models:
  1. qwen2.5-finetuned (4.7 GB) ⭐ Recommended
  2. llama2 (3.8 GB)
  3. mistral (4.1 GB)
  4. codellama (6.2 GB)

Which model would you like to use? (Enter number or name):
>
```

**Step 2: Handle model selection**

```
User input: "2" (llama2)

⚠️  Warning: llama2 is not fine-tuned for security classification.
   It may not output the required 6-parameter JSON format.

Recommended: qwen2.5-finetuned

Do you want to:
A) Continue with llama2 anyway (may fail)
B) Use qwen2.5-finetuned instead (recommended)
C) Cancel and install qwen2.5-finetuned first

Your choice:
```

**Step 3: If model not found**

```
Model 'qwen2.5-finetuned' not found in Ollama.

Would you like to:
A) Install it now (ollama pull qwen2.5-finetuned)
B) Use a different available model
C) Cancel classification

Your choice:
```

### Phase 3: Classification Execution

**Step 1: Confirm configuration**

```
Configuration Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL:    http://localhost:11434/api/chat
Model:  qwen2.5-finetuned ⭐
Status: ✓ Connected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Prompt to classify:
"[user's prompt]"

Proceed with classification? (Y/n):
```

**Step 2: Execute classification**

```
Classifying prompt with qwen2.5-finetuned...
⏳ Processing... (0.8s)
✓ Classification complete!

Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Intent:    Benign (Low)
Persona:   Neutral/Default State (Low)
Pattern:   Normal (Low)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Overall Risk: LOW ✓
```

### Phase 4: Error Handling & Recovery

**Scenario 1: Classification fails with selected model**

```
❌ Classification failed!

Error: Missing required fields in response
Model 'llama2' returned:
{
  "response": "This prompt is benign."
}

Expected format:
{
  "Intent_Category": "...",
  "Generic_Persona_Category": "...",
  ...
}

This model is not compatible with security classification.

Options:
A) Retry with qwen2.5-finetuned (recommended)
B) Try different model
C) Cancel

Your choice:
```

**Scenario 2: Network timeout**

```
❌ Classification timeout after 10 seconds.

Possible causes:
- Model is too large for your system
- Ollama is overloaded
- Network connection issue

Options:
A) Retry with same model
B) Try smaller model (qwen2.5-finetuned is 4.7GB)
C) Check Ollama status
D) Cancel

Your choice:
```

---

## Implementation

### Core Function

```python
def interactive_classify_prompt(prompt):
    """
    Interactive prompt classification with configuration wizard

    This function handles:
    1. Configuration gathering
    2. Validation
    3. Model selection
    4. Classification
    5. Error recovery
    """

    # Phase 1: Get configuration
    config = get_or_ask_configuration()

    # Phase 2: Validate & discover models
    validation = validate_ollama(config['url'])

    if not validation['success']:
        handle_connection_error(validation['error'])
        return

    # Phase 3: Model selection
    model = interactive_model_selection(
        available_models=validation['models'],
        requested_model=config.get('model'),
        recommended='qwen2.5-finetuned'
    )

    # Phase 4: Confirm and execute
    if confirm_classification(config, model, prompt):
        result = execute_classification(config['url'], model, prompt)

        if result['success']:
            display_results(result['classification'])
        else:
            handle_classification_error(result['error'], model)

    return result
```

### Configuration Functions

```python
def get_or_ask_configuration():
    """Get configuration from .env or ask user"""

    # Try loading from .env
    env_config = load_from_env()

    if env_config:
        print("Found existing configuration:")
        print(f"  URL: {env_config['url']}")
        print(f"  Model: {env_config['model']}")
        print()
        choice = input("Use these settings? (Y/n): ").strip().lower()

        if choice in ['', 'y', 'yes']:
            return env_config

    # Ask user for configuration
    print("\nPlease provide Ollama configuration:")

    url = input("1. Ollama URL [http://localhost:11434]: ").strip()
    if not url:
        url = "http://localhost:11434"

    if not url.endswith('/api/chat'):
        url = f"{url}/api/chat"

    model = input("2. Model name (or 'auto' to choose): ").strip()

    return {
        'url': url,
        'model': model if model and model != 'auto' else None
    }
```

```python
def validate_ollama(url):
    """Validate Ollama connection and get available models"""

    base_url = url.replace('/api/chat', '')

    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)

        if response.status_code == 200:
            models = response.json().get('models', [])

            print(f"\n✓ Ollama connection successful!")
            print(f"  Found {len(models)} model(s)")

            return {
                'success': True,
                'models': models
            }
        else:
            return {
                'success': False,
                'error': f"Ollama returned status code {response.status_code}"
            }

    except requests.exceptions.ConnectionError:
        return {
            'success': False,
            'error': "Cannot connect to Ollama. Is it running?\n\n  Start with: ollama serve"
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"Unexpected error: {str(e)}"
        }
```

```python
def interactive_model_selection(available_models, requested_model, recommended):
    """
    Guide user through model selection with validation

    Args:
        available_models: List of models from Ollama
        requested_model: User's requested model (or None)
        recommended: Recommended model name
    """

    # Display available models
    print("\nAvailable models:")
    print("━" * 50)

    for idx, model in enumerate(available_models, 1):
        name = model.get('name', 'unknown')
        size_gb = model.get('size', 0) / 1_000_000_000
        marker = " ⭐ Recommended" if recommended in name else ""

        print(f"  {idx}. {name} ({size_gb:.1f} GB){marker}")

    print("━" * 50)

    # If user already specified a model, validate it
    if requested_model:
        model_names = [m.get('name', '') for m in available_models]

        if any(requested_model in name for name in model_names):
            # Model exists, check if it's recommended
            if recommended not in requested_model:
                print(f"\n⚠️  Warning: '{requested_model}' is not the recommended model.")
                print(f"   Recommended: {recommended}")
                print()
                choice = input("Continue with this model anyway? (y/N): ").strip().lower()

                if choice not in ['y', 'yes']:
                    requested_model = None  # Ask user to choose
        else:
            # Model doesn't exist
            print(f"\n❌ Model '{requested_model}' not found!")
            print(f"\nTo install: ollama pull {requested_model}")
            print()
            choice = input("Choose a different model? (Y/n): ").strip().lower()

            if choice in ['', 'y', 'yes']:
                requested_model = None
            else:
                return None  # Cancel

    # Ask user to select model
    if not requested_model:
        print()
        selection = input("Select model (number or name): ").strip()

        # Handle number selection
        if selection.isdigit():
            idx = int(selection) - 1
            if 0 <= idx < len(available_models):
                requested_model = available_models[idx].get('name')
            else:
                print(f"Invalid selection: {selection}")
                return None
        else:
            requested_model = selection

    return requested_model
```

```python
def execute_classification(url, model, prompt):
    """Execute the actual classification"""

    system_prompt = """You are a security classification model. Your ONLY job is to output classification JSON.

REQUIRED OUTPUT FORMAT (copy this structure exactly):
{
  "Intent_Category": "value",
  "Generic_Persona_Category": "value",
  "Pattern": "value",
  "Intent_Risk_Severity": "value",
  "Persona_Risk_Severity": "value",
  "Pattern_Risk_Severity": "value"
}

RULES:
1. ONLY output the JSON object
2. DO NOT include the original prompt
3. DO NOT add explanations"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Classify this prompt:\nWhat is 2+2?"},
        {"role": "assistant", "content": '{"Intent_Category": "Benign", "Generic_Persona_Category": "Neutral/Default State", "Pattern": "Normal", "Intent_Risk_Severity": "Low", "Persona_Risk_Severity": "Low", "Pattern_Risk_Severity": "Low"}'},
        {"role": "user", "content": f"Classify this prompt:\n{prompt}"}
    ]

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "format": "json"
    }

    try:
        print(f"\nClassifying with {model}...")
        print("⏳ Processing...")

        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()

        result = response.json()
        content = result.get('message', {}).get('content', '')

        classification = json.loads(content)

        # Validate required fields
        required = [
            "Intent_Category",
            "Generic_Persona_Category",
            "Pattern",
            "Intent_Risk_Severity",
            "Persona_Risk_Severity",
            "Pattern_Risk_Severity"
        ]

        missing = [f for f in required if f not in classification]

        if missing:
            return {
                'success': False,
                'error': f"Missing fields: {', '.join(missing)}",
                'raw_output': content
            }

        print("✓ Classification complete!")

        return {
            'success': True,
            'classification': classification
        }

    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': "Classification timeout after 30 seconds"
        }
    except json.JSONDecodeError:
        return {
            'success': False,
            'error': "Model returned invalid JSON",
            'raw_output': content
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
```

### Display Functions

```python
def display_results(classification):
    """Display classification results in a clean format"""

    print("\nResults:")
    print("━" * 50)
    print(f"Intent:    {classification['Intent_Category']} ({classification['Intent_Risk_Severity']})")
    print(f"Persona:   {classification['Generic_Persona_Category']} ({classification['Persona_Risk_Severity']})")
    print(f"Pattern:   {classification['Pattern']} ({classification['Pattern_Risk_Severity']})")
    print("━" * 50)

    # Determine overall risk
    severities = [
        classification['Intent_Risk_Severity'],
        classification['Persona_Risk_Severity'],
        classification['Pattern_Risk_Severity']
    ]

    if 'Critical' in severities:
        overall = 'CRITICAL'
        icon = '❌'
    elif 'High' in severities:
        overall = 'HIGH'
        icon = '⚠️'
    elif 'Medium' in severities:
        overall = 'MEDIUM'
        icon = '⚡'
    else:
        overall = 'LOW'
        icon = '✓'

    print(f"\nOverall Risk: {overall} {icon}")
```

---

## Usage Example

### Invoking the Skill

```bash
> classify prompt: "What is the capital of France?"
```

### Interactive Session

```
Checking for Ollama configuration...

Found .env file with:
- OLLAMA_URL: http://localhost:11434/api/chat
- OLLAMA_MODEL: qwen2.5-finetuned

Use these settings? (Y/n): y

✓ Ollama connection successful!
  Found 4 model(s)

Available models:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. qwen2.5-finetuned (4.7 GB) ⭐ Recommended
  2. llama2 (3.8 GB)
  3. mistral (4.1 GB)
  4. codellama (6.2 GB)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Using configured model: qwen2.5-finetuned ⭐

Configuration Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL:    http://localhost:11434/api/chat
Model:  qwen2.5-finetuned ⭐
Status: ✓ Connected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Prompt to classify:
"What is the capital of France?"

Proceed? (Y/n): y

Classifying with qwen2.5-finetuned...
⏳ Processing...
✓ Classification complete!

Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Intent:    Benign (Low)
Persona:   Neutral/Default State (Low)
Pattern:   Normal (Low)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Overall Risk: LOW ✓
```

---

## Quality Standards

- ✅ **Interactive**: Asks for configuration when needed
- ✅ **Validating**: Verifies all inputs before proceeding
- ✅ **Helpful**: Suggests alternatives when issues occur
- ✅ **Clear**: Provides actionable error messages
- ✅ **Robust**: Handles all edge cases gracefully
- ✅ **Self-contained**: No external UI dependencies

## Dependencies

- **Ollama** (must be running)
- **At least one model installed**
- **requests** library (Python)
- **json** library (Python)

---

**Version**: 3.0 (Interactive Skill)
**Last Updated**: 2026-03-08
**Status**: Production-Ready
**UI Dependencies**: None (fully self-contained)
