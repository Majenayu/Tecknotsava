# ScamShield Android App

## 🛡️ AI-Powered Call Protection for Your Real Phone Number

ScamShield Android App intercepts calls to **your actual phone number** and screens them with AI before they reach you. No virtual numbers needed!

## 🎯 How It Works

1. **Install ScamShield app** on your Android phone
2. **Grant call screening permissions** (one-time setup)
3. **AI automatically answers** unknown calls to your real number
4. **Screens callers** with 4 security questions
5. **Blocks scam calls** automatically
6. **Connects legitimate calls** to you

## 📱 Features

- ✅ **Real Phone Number** - Uses your actual mobile number
- ✅ **AI Voice Assistant** - Speaks and listens to callers
- ✅ **Scam Detection** - Advanced keyword and AI analysis
- ✅ **Automatic Blocking** - High-risk calls terminated instantly
- ✅ **Live Dashboard** - View all call attempts and threat scores
- ✅ **No Monthly Fees** - One-time install, lifetime protection

## 🚀 Installation

### Prerequisites
- Android 7.0+ (API level 24+)
- Microphone and phone permissions
- Internet connection

### Setup Steps

1. **Install the APK** on your Android device
2. **Open ScamShield app**
3. **Tap "Enable ScamShield"**
4. **Grant required permissions:**
   - Phone access
   - Microphone access
   - Call screening role
5. **Done!** Your phone is now protected

## 🔧 Technical Details

### Android APIs Used
- **CallScreeningService** - Intercepts incoming calls
- **TextToSpeech** - AI voice responses
- **SpeechRecognizer** - Understands caller responses
- **RoleManager** - Call screening permissions

### Backend Integration
- Connects to your existing ScamShield web backend
- Real-time threat analysis with Groq AI
- Live dashboard updates

### Permissions Required
```xml
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.BIND_SCREENING_SERVICE" />
```

## 📊 Call Flow

```
Unknown caller dials YOUR number
        ↓
ScamShield app intercepts call
        ↓
AI answers: "Hello, ScamShield screening..."
        ↓
Asks 4 security questions
        ↓
Analyzes responses for scam patterns
        ↓
HIGH risk → Hangs up automatically
LOW risk → Rings your phone normally
```

## 🎯 Benefits Over Virtual Numbers

| Feature | Virtual Numbers | ScamShield App |
|---------|----------------|----------------|
| **Your Real Number** | ❌ Need new number | ✅ Uses your existing number |
| **Cost** | Monthly fees | One-time install |
| **Setup** | Complex configuration | Simple app install |
| **User Experience** | Callers confused by new number | Seamless for legitimate callers |

## 🔒 Privacy & Security

- **On-device processing** - Voice recognition happens locally
- **Encrypted communication** - All API calls use HTTPS
- **No call recording** - Only transcripts are analyzed
- **User control** - You can disable anytime

## 📱 Screenshots

### Main Screen
- Status indicator (Active/Inactive)
- Enable/Disable button
- View Dashboard link

### Call Screening in Action
- AI voice greeting
- Real-time question asking
- Automatic threat assessment

## 🛠️ Development

### Build Requirements
- Android Studio 4.0+
- Android SDK 34
- Java 8+

### Build Commands
```bash
./gradlew assembleDebug    # Debug build
./gradlew assembleRelease  # Release build
```

### Testing
```bash
./gradlew test            # Unit tests
./gradlew connectedAndroidTest  # Integration tests
```

## 🚀 Deployment

1. **Build release APK**
2. **Sign with your keystore**
3. **Install on target device**
4. **Configure backend URL** in app settings

## 🔧 Configuration

Update the API base URL in `ScamShieldScreeningService.java`:
```java
private static final String API_BASE_URL = "https://tecknotsava.onrender.com";
```

## 📞 Testing

1. **Install app and enable call screening**
2. **Call your number from another phone**
3. **Listen to AI greeting and questions**
4. **Check dashboard for call analysis**

## 🆘 Troubleshooting

### App not intercepting calls
- Check call screening role is granted
- Verify permissions are enabled
- Restart phone after installation

### AI not speaking
- Check microphone permissions
- Ensure TTS is initialized
- Test with device volume up

### Backend connection issues
- Verify internet connection
- Check API URL configuration
- Review app logs for errors

## 📈 Future Enhancements

- **Custom voice training** - Personalized AI voice
- **Whitelist management** - Trusted caller lists
- **Advanced analytics** - Detailed scam patterns
- **Multi-language support** - Regional language screening

This Android app solves your core problem: **No need for virtual numbers or international calling charges!** Your existing phone number becomes AI-protected.