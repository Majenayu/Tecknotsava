package com.scamshield.app;

import android.Manifest;
import android.app.role.RoleManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.telecom.TelecomManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

/**
 * ScamShield Android App - Main Activity
 * Intercepts calls to your real phone number and screens them with AI
 */
public class MainActivity extends AppCompatActivity {
    
    private static final int REQUEST_CALL_SCREENING_ROLE = 1;
    private static final int REQUEST_PERMISSIONS = 2;
    
    private TextView statusText;
    private Button enableButton;
    private Button viewDashboardButton;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        initViews();
        checkPermissions();
        updateStatus();
    }
    
    private void initViews() {
        statusText = findViewById(R.id.statusText);
        enableButton = findViewById(R.id.enableButton);
        viewDashboardButton = findViewById(R.id.viewDashboardButton);
        
        enableButton.setOnClickListener(v -> requestCallScreeningRole());
        viewDashboardButton.setOnClickListener(v -> openDashboard());
    }
    
    private void checkPermissions() {
        String[] permissions = {
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.CALL_PHONE,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.INTERNET
        };
        
        boolean allGranted = true;
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) 
                != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        
        if (!allGranted) {
            ActivityCompat.requestPermissions(this, permissions, REQUEST_PERMISSIONS);
        }
    }
    
    private void requestCallScreeningRole() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            RoleManager roleManager = (RoleManager) getSystemService(ROLE_SERVICE);
            Intent intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING);
            startActivityForResult(intent, REQUEST_CALL_SCREENING_ROLE);
        } else {
            Toast.makeText(this, "Please set ScamShield as default call screening app in Settings", 
                         Toast.LENGTH_LONG).show();
        }
    }
    
    private void updateStatus() {
        if (isCallScreeningEnabled()) {
            statusText.setText("✅ ScamShield is ACTIVE\n\nYour phone is protected from scam calls!");
            statusText.setTextColor(getColor(android.R.color.holo_green_dark));
            enableButton.setText("Disable ScamShield");
        } else {
            statusText.setText("❌ ScamShield is INACTIVE\n\nTap below to enable call screening");
            statusText.setTextColor(getColor(android.R.color.holo_red_dark));
            enableButton.setText("Enable ScamShield");
        }
    }
    
    private boolean isCallScreeningEnabled() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            RoleManager roleManager = (RoleManager) getSystemService(ROLE_SERVICE);
            return roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING);
        }
        return false;
    }
    
    private void openDashboard() {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(android.net.Uri.parse("https://tecknotsava.onrender.com"));
        startActivity(intent);
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        
        if (requestCode == REQUEST_CALL_SCREENING_ROLE) {
            updateStatus();
            if (resultCode == RESULT_OK) {
                Toast.makeText(this, "ScamShield enabled! Your calls are now protected.", 
                             Toast.LENGTH_LONG).show();
            }
        }
    }
    
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        
        if (requestCode == REQUEST_PERMISSIONS) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            
            if (!allGranted) {
                Toast.makeText(this, "Permissions required for ScamShield to work", 
                             Toast.LENGTH_LONG).show();
            }
        }
    }
}