"""
check_connectivity.py
=====================
Tiny round-trip ping to each provider so we know keys, billing, and SDKs all work
before we spend real money. Prints OK/FAIL per provider.
"""
import truststore
truststore.inject_into_ssl()

import os
import sys
import time
import os
import sys
import time

from dotenv import load_dotenv
load_dotenv()

PROMPT = "Reply with the single word OK and nothing else."

def check_openai():
    name = "OpenAI"
    if not os.environ.get("OPENAI_API_KEY"):
        return name, False, "OPENAI_API_KEY not set"
    try:
        from openai import OpenAI
        client = OpenAI()
        t0 = time.time()
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": PROMPT}],
            max_tokens=5,
        )
        text = (r.choices[0].message.content or "").strip()
        return name, True, f"reply='{text}' latency={time.time()-t0:.2f}s"
    except Exception as exc:
        return name, False, str(exc)

def check_anthropic():
    name = "Anthropic"
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return name, False, "ANTHROPIC_API_KEY not set"
    try:
        import anthropic
        client = anthropic.Anthropic()
        t0 = time.time()
        r = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=5,
            messages=[{"role": "user", "content": PROMPT}],
        )
        text = "".join(b.text for b in r.content if getattr(b, "type", None) == "text").strip()
        return name, True, f"reply='{text}' latency={time.time()-t0:.2f}s"
    except Exception as exc:
        return name, False, str(exc)

def check_google():
    name = "Google"
    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        return name, False, "GEMINI_API_KEY (or GOOGLE_API_KEY) not set"
    try:
        from google import genai
        client = genai.Client(
            api_key=os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"),
        )
        t0 = time.time()
        r = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=PROMPT,
        )
        text = (getattr(r, "text", "") or "").strip()
        return name, True, f"reply='{text}' latency={time.time()-t0:.2f}s"
    except Exception as exc:
        return name, False, str(exc)
    
def main():
    results = [check_openai(), check_anthropic(), check_google()]
    print()
    print("Connectivity check results")
    print("==========================")
    any_fail = False
    for name, ok, detail in results:
        status = "OK  " if ok else "FAIL"
        print(f"  [{status}] {name:10s} - {detail}")
        if not ok:
            any_fail = True
    print()
    sys.exit(1 if any_fail else 0)

if __name__ == "__main__":
    main()