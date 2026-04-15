package com.scamshield.app;

import android.net.Uri;
import android.telecom.Call;
import android.telecom.CallResponse;
import android.telecom.CallScreeningService;
import android.telecom.Connection;
import android.util.Log;
import android.speech.tts.TextToSpeech;
import android.speech.SpeechRecognizer;
import android.speech.RecognitionListener;
import android.speech.RecognizerIntent;
import android.content.Intent;
import android.os.Bundle;
import java.util.ArrayList;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import okhttp3.*;
import org.json.JSONObject;
import org.json.JSONArray;

/**
 * ScamShield Call Screening Service
 * Intercepts incoming calls and screens them with AI
 */
public class ScamShieldScreeningService extends CallScreeningService implements TextToSpeech.OnInitListener {
    
    private static final String TAG = "ScamShieldScreening";
    private static final String API_BASE_URL = "https://tecknotsava.onrender.com";
    
    private TextToSpeech tts;
    private SpeechRecognizer speechRecognizer;
    private OkHttpClient httpClient;
    
    private String currentCallId;
    private int currentQuestion = 0;
    private ArrayList<String> responses = new ArrayList<>();
    
    private final String[] QUESTIONS = {
        "What is the purpose of your call today?",
        "Can you verify your identity and the organisation you represent?",
        "Is this a time-sensitive or urgent matter?",
        "Will you need me to share any account details, OTP, or personal information?"
    };
    
    @Override
    public void onCreate() {
        super.onCreate();
        
        tts = new TextToSpeech(this, this);
        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(this);
        speechRecognizer.setRecognitionListener(new CallRecognitionListener());
        httpClient = new OkHttpClient();
        
        Log.d(TAG, "ScamShield Screening Service initialized");
    }
    
    @Override
    public void onScreenCall(Call.Details callDetails) {
        Log.d(TAG, "Screening incoming call");
        
        boolean isIncoming = callDetails.getCallDirection() == Call.Details.DIRECTION_INCOMING;
        
        if (!isIncoming) {
            respondToCall(callDetails, new CallResponse.Builder().build());
            return;
        }
        
        Uri handle = callDetails.getHandle();
        String phoneNumber = handle.getSchemeSpecificPart();
        
        Log.d(TAG, "Incoming call from: " + phoneNumber);
        
        if (isKnownContact(phoneNumber)) {
            respondToCall(callDetails, new CallResponse.Builder().build());
            return;
        }
        
        currentCallId = callDetails.getTelecomCallId();
        currentQuestion = 0;
        responses.clear();
        
        CallResponse response = new CallResponse.Builder()
            .setDisallowCall(false)
            .setRejectCall(false)
            .setSilenceCall(true)
            .setSkipCallLog(false)
            .setSkipNotification(true)
            .build();
            
        respondToCall(callDetails, response);
        startScreeningConversation(phoneNumber);
    }
    
    private boolean isKnownContact(String phoneNumber) {
        return false; // Screen all calls for now
    }
    
    private void startScreeningConversation(String phoneNumber) {
        sendCallDataToBackend(phoneNumber, "CALL_STARTED", "");
        
        String greeting = "Hello. You have reached ScamShield security screening. " +
                         "Please answer a few questions to connect your call. " +
                         "Question one: " + QUESTIONS[0];
        
        speakText(greeting, () -> startListening());
    }
    
    private void speakText(String text, Runnable onComplete) {
        if (tts != null && !tts.isSpeaking()) {
            tts.speak(text, TextToSpeech.QUEUE_FLUSH, null, "scamshield_tts");
            
            new Thread(() -> {
                while (tts.isSpeaking()) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
                if (onComplete != null) {
                    onComplete.run();
                }
            }).start();
        }
    }
    
    private void startListening() {
        Intent intent = new Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH);
        intent.putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM);
        intent.putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault());
        intent.putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, true);
        
        speechRecognizer.startListening(intent);
    }
    
    private class CallRecognitionListener implements RecognitionListener {
        @Override
        public void onResults(Bundle results) {
            ArrayList<String> matches = results.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION);
            if (matches != null && !matches.isEmpty()) {
                String response = matches.get(0);
                Log.d(TAG, "Caller response: " + response);
                
                responses.add(response);
                sendCallDataToBackend(currentCallId, "RESPONSE_" + (currentQuestion + 1), response);
                
                currentQuestion++;
                
                if (currentQuestion < QUESTIONS.length) {
                    String nextQuestion = "Question " + (currentQuestion + 1) + ": " + QUESTIONS[currentQuestion];
                    speakText(nextQuestion, () -> startListening());
                } else {
                    getFinalVerdict();
                }
            }
        }
        
        @Override
        public void onError(int error) {
            Log.e(TAG, "Speech recognition error: " + error);
            if (currentQuestion < QUESTIONS.length) {
                speakText("I didn't catch that. " + QUESTIONS[currentQuestion], () -> startListening());
            }
        }
        
        @Override public void onReadyForSpeech(Bundle params) {}
        @Override public void onBeginningOfSpeech() {}
        @Override public void onRmsChanged(float rmsdB) {}
        @Override public void onBufferReceived(byte[] buffer) {}
        @Override public void onEndOfSpeech() {}
        @Override public void onPartialResults(Bundle partialResults) {}
        @Override public void onEvent(int eventType, Bundle params) {}
    }
    
    private void getFinalVerdict() {
        CompletableFuture.supplyAsync(() -> {
            try {
                JSONObject requestBody = new JSONObject();
                requestBody.put("call_id", currentCallId);
                requestBody.put("responses", new JSONArray(responses));
                
                RequestBody body = RequestBody.create(
                    requestBody.toString(),
                    MediaType.parse("application/json")
                );
                
                Request request = new Request.Builder()
                    .url(API_BASE_URL + "/api/analyze-call")
                    .post(body)
                    .build();
                
                Response response = httpClient.newCall(request).execute();
                String responseBody = response.body().string();
                
                return new JSONObject(responseBody);
                
            } catch (Exception e) {
                Log.e(TAG, "Error getting verdict", e);
                return null;
            }
        }).thenAccept(result -> {
            if (result != null) {
                try {
                    String verdict = result.getString("verdict");
                    int threatScore = result.getInt("threat_score");
                    handleFinalVerdict(verdict, threatScore);
                } catch (Exception e) {
                    Log.e(TAG, "Error parsing verdict", e);
                    handleFinalVerdict("LOW", 0);
                }
            } else {
                handleFinalVerdict("LOW", 0);
            }
        });
    }
    
    private void handleFinalVerdict(String verdict, int threatScore) {
        Log.d(TAG, "Final verdict: " + verdict + " (Score: " + threatScore + ")");
        
        if ("HIGH".equals(verdict)) {
            speakText("This call has been flagged as high risk and will now be disconnected.", () -> {
                Log.d(TAG, "Terminating high-risk call");
            });
        } else if ("MEDIUM".equals(verdict)) {
            speakText("Thank you. Exercise caution with this call. Connecting now.", () -> {
                connectCallToUser();
            });
        } else {
            speakText("Thank you. Connecting you now.", () -> {
                connectCallToUser();
            });
        }
    }
    
    private void connectCallToUser() {
        Log.d(TAG, "Connecting call to user");
    }
    
    private void sendCallDataToBackend(String phoneNumber, String event, String data) {
        CompletableFuture.runAsync(() -> {
            try {
                JSONObject requestBody = new JSONObject();
                requestBody.put("phone_number", phoneNumber);
                requestBody.put("event", event);
                requestBody.put("data", data);
                requestBody.put("timestamp", System.currentTimeMillis());
                
                RequestBody body = RequestBody.create(
                    requestBody.toString(),
                    MediaType.parse("application/json")
                );
                
                Request request = new Request.Builder()
                    .url(API_BASE_URL + "/api/call-event")
                    .post(body)
                    .build();
                
                Response response = httpClient.newCall(request).execute();
                Log.d(TAG, "Sent call data to backend: " + response.code());
                
            } catch (Exception e) {
                Log.e(TAG, "Error sending call data to backend", e);
            }
        });
    }
    
    @Override
    public void onInit(int status) {
        if (status == TextToSpeech.SUCCESS) {
            int result = tts.setLanguage(Locale.US);
            if (result == TextToSpeech.LANG_MISSING_DATA || result == TextToSpeech.LANG_NOT_SUPPORTED) {
                Log.e(TAG, "TTS language not supported");
            } else {
                Log.d(TAG, "TTS initialized successfully");
            }
        } else {
            Log.e(TAG, "TTS initialization failed");
        }
    }
    
    @Override
    public void onDestroy() {
        if (tts != null) {
            tts.stop();
            tts.shutdown();
        }
        if (speechRecognizer != null) {
            speechRecognizer.destroy();
        }
        super.onDestroy();
    }
}