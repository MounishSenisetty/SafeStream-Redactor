# Structural / Class Model

Core types and their relationships. **Corrected against the implementation**
(`entities.py`, `policy.py`, `report.py`, `redactor.py`): the `EntityType`
enum, the `Detection` fields (`text`, `meta`), and `RedactionStats` now match
the code exactly.

```mermaid
classDiagram
    class Redactor {
        +RedactionPolicy policy
        +float min_confidence
        +int chunk_size
        +int overlap
        +Calibrator calibrator
        +list~str~ detector_names
        +detect(text) list~Detection~
        +redact(text) str
        +redact_stream(chunks, stats) Iterator~str~
        +redact_file(input, output) RedactionStats
    }
    class RedactionPolicy {
        +RedactionMode mode
        +str replacement
        +dict replacements
        +int mask_keep_last
        +str mask_char
        +bytes hmac_key
        +int pseudonym_length
        +render(detection) str
        +apply(text, detections) str
    }
    class Detection {
        +int start
        +int end
        +str text
        +EntityType entity_type
        +float confidence
        +str source
        +dict meta
        +overlaps(other) bool
    }
    class Detector {
        <<protocol>>
        +str name
        +detect(text) list~Detection~
    }
    class CustomDetector
    class DeterministicDetector
    class EntropyDetector
    class NERDetector
    class ContextualScorer
    class Calibrator {
        +predict_one(detection) float
    }
    class RedactionStats {
        +Counter counts
        +int chars_in
        +int chars_out
        +int decode_replacements
        +int total
        +add_segment(segment, redacted, detections)
        +merge(other)
        +summary() str
    }
    class RedactionMode {
        <<enumeration>>
        REPLACE
        MASK
        PSEUDONYMIZE
    }
    class EntityType {
        <<enumeration>>
        EMAIL
        PHONE
        CREDIT_CARD
        SSN
        IPV4
        IPV6
        AWS_KEY
        AWS_SECRET
        GITHUB_TOKEN
        API_KEY
        JWT
        PRIVATE_KEY
        SLACK_TOKEN
        SLACK_WEBHOOK
        STRIPE_KEY
        GOOGLE_API_KEY
        SENDGRID_KEY
        TWILIO_KEY
        NPM_TOKEN
        OPENAI_KEY
        ANTHROPIC_KEY
        URL_CREDENTIALS
        SECRET
        PERSON
        ORG
        LOC
        CUSTOM
    }

    Redactor --> RedactionPolicy
    Redactor --> Detector
    Redactor --> RedactionStats
    Redactor --> Calibrator
    Detector <|.. CustomDetector
    Detector <|.. DeterministicDetector
    Detector <|.. EntropyDetector
    Detector <|.. NERDetector
    Detector <|.. ContextualScorer
    Detector --> Detection
    Detection --> EntityType
    RedactionPolicy --> RedactionMode
    RedactionPolicy --> Detection
    Redactor "1" --> "*" Detection
```
