# AI WatchDog

AI WatchDog is a JavaFX desktop prototype for AI-driven phishing detection and secure access. It is explicitly a **prototype simulation**: it does not monitor Chrome or Edge, block operating-system traffic, or run a trained production ML model.

## Run

Requirements: JDK 17+ and Maven 3.9+.

```powershell
cd Frontend
mvn clean javafx:run
```

Demo flow: start protection, complete setup, simulate a browser event, watch the AI analysis, inspect the result, then review Threat Center, Activity, and AI Insights. The URL Scanner is a secondary manual demonstration tool.

The detection layer is exposed through `PhishingDetectionEngine`; `DemoPhishingDetectionEngine` can later be replaced with a REST-backed Python implementation. Supporting services include URL feature extraction, adaptive access decisions, and demo event generation.
