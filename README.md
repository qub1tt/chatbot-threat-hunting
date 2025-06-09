# SIEMGuardian AI

SIEMGuardian AI is an AI-powered threat hunting assistant that helps security analysts create Sigma rules and convert them to EQL for Elasticsearch SIEM. This project integrates AI capabilities with SIEM systems for enhanced threat detection.

## Project Overview

SIEMGuardian AI helps security teams by:
- Converting natural language descriptions into formal Sigma detection rules
- Translating Sigma rules to Elasticsearch Query Language (EQL) for ELK SIEM
- Providing an intuitive interface for security analysts to leverage AI in threat hunting
- Storing and managing detection rules for future reference

The name "SIEMGuardian AI" represents the tool's role in enhancing SIEM capabilities with artificial intelligence to guard against threats.

## Features

- **AI-Generated Sigma Rules**: Input your threat hunting requirements in natural language
- **EQL Translation**: Automatically convert Sigma rules to Elasticsearch Query Language
- **User-Friendly Interface**: Clean, ChatGPT-like interface for easy interaction
- **Rule History**: Keep track of previously generated rules and queries

## Technology Stack

- **Frontend**: React with TypeScript and Tailwind CSS
- **Backend**: Flask API with SigmAIQ integration
- **AI**: Leverages OpenAI's models for threat intelligence
- **SIEM Integration**: Generates EQL queries compatible with Elasticsearch SIEM

## Prerequisites

- Node.js 16+ and npm/yarn
- Python 3.8+
- OpenAI API key

## Installation

### Frontend Setup

```bash
# Clone the repository
git clone https://github.com/your-username/siemguardian-ai.git
cd siemguardian-ai

# Install dependencies
npm install

# Start the development server
npm run dev
```

### Backend Setup

```bash
# Navigate to the api directory
cd api

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set your OpenAI API key
# Option 1: Set as environment variable
export OPENAI_API_KEY=your-api-key-here  # On Windows: set OPENAI_API_KEY=your-api-key-here

# Option 2: Create a .env file in the api directory with:
# OPENAI_API_KEY=your-api-key-here

# Start the Flask server
python app.py
```

## Usage

1. Start both the frontend and backend servers (or use `npm run start` to run both)
2. Open your browser to `http://localhost:5173` (or the port shown in your terminal)
3. Enter your threat hunting requirements in natural language
4. The system will generate a Sigma rule and its EQL translation
5. Use the EQL in your Elasticsearch SIEM to create alerts

## Project Structure

```
siemguardian-ai/
├── src/                 # Frontend React code
│   ├── components/      # React components
│   ├── hooks/           # Custom React hooks
│   ├── App.tsx          # Main application component
│   └── main.tsx         # Entry point
├── api/                 # Backend Flask API
│   ├── app.py           # API endpoints
│   └── requirements.txt # Python dependencies
├── public/              # Static assets
└── README.md            # This file
```

## License

MIT

## Acknowledgements

- [SigmAIQ](https://github.com/sigmaiq/sigmaiq) for Sigma rule generation capabilities
- [Sigma](https://github.com/SigmaHQ/sigma) for the rule specification
- [Elasticsearch](https://www.elastic.co/) for SIEM integration
