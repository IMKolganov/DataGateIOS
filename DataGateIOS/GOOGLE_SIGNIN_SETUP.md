# Google Sign-In setup

1. **Google Cloud Console**  
   Create an OAuth 2.0 Client ID for iOS (Bundle ID must match your app).

2. **Xcode – Info**  
   In the target’s **Info** tab, add:
   - **GIDClientID**: your iOS client ID (e.g. `123-xxx.apps.googleusercontent.com`).

3. **URL scheme**  
   In **Info** → **URL Types**, add a scheme with:
   - **URL Scheme**: reversed client ID (e.g. `com.googleusercontent.apps.123-xxx`).
   - **Role**: Editor (or leave default).

4. **Run**  
   Sign in with Google will open the Google flow and send the idToken to your backend.
