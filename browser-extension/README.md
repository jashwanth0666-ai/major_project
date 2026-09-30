# AI WatchDog Chromium URL Monitor

This Manifest V3 extension provides a browser activity source for Chrome and Chromium based Edge. It observes the active tab after activation/navigation and sends the sanitized URL to the local Spring endpoint `POST /api/v1/analyze`.

## Privacy and behavior

- It handles only HTTP and HTTPS active tabs. Browser settings, local files, extension pages, and other schemes are ignored.
- Credentials, query strings, and fragments are removed before the URL is sent. A path containing common credential terms or a long opaque segment is reduced to `/`; otherwise the ML service evaluates the origin and path.
- It does not read page contents, cookies, passwords, form values, or command data.
- Duplicate normalized URLs are suppressed for 60 seconds in the extension worker.
- It sends only to `localhost:8080` or `127.0.0.1:8080`; it does not send data to a remote service.
- It does not cancel navigation or enforce `WARN`/`BLOCK`; results are evaluated and logged by Spring and appear in AI WatchDog history.
- The `tabs` permission is required for the extension to observe active-tab URLs. The browser displays the permission disclosure when the extension is loaded.

## Load for development

1. Start FastAPI and Spring Boot using the project run guide.
2. In Chrome or Edge, open the browser's extensions page and enable Developer mode.
3. Choose **Load unpacked** and select this `browser-extension` directory.
4. Open an HTTP/HTTPS tab, then check the JavaFX Activity page or `GET /api/security-events` for its sanitized analysis.

The extension is source code only; this project does not install it into a browser profile.
