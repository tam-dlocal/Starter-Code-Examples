package com.example;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class GetPayoutRequest {

    // Method to generate HMAC-SHA256 signature
    public static String generateHMACSHA256Signature(String payload, String secretKey) throws Exception {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hashBytes = mac.doFinal(payloadBytes);

        StringBuilder hashString = new StringBuilder();
        for (byte b : hashBytes) {
            hashString.append(String.format("%02x", b));
        }
        return hashString.toString();
    }

    public static void main(String[] args) {
        try {
            // Endpoint and credentials
            String apiUrl = "https://sandbox.dlocal.com/payouts";
                    String login = "x"; // Replace with actual login
        String transKey = "x"; // Replace with actual transaction key
            String secretKey = "x"; // Replace with actual secret key

            // You can use either payout_id or external_id
            String payoutId = "1599264"; // Replace with actual payout ID
            // String externalId = "example-id"; // Alternatively, use external ID

            // Build the URL with query parameters
            String queryParams = "payout_id=" + payoutId;
            String fullUrl = apiUrl + "?" + queryParams;
            
            // Get the current UTC timestamp in ISO format
            String timestamp = ZonedDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);
            System.out.println("Using timestamp: " + timestamp);

            // Generate signature with login + timestamp
            String message = login + timestamp;
            String signature = generateHMACSHA256Signature(message, secretKey);
            System.out.println("Using message for signature: " + message);
            System.out.println("Using signature: " + signature);

            // Prepare and send the HTTP GET request
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(fullUrl);

            // Set headers including the signature
            httpGet.setHeader("X-Date", timestamp);
            httpGet.setHeader("X-Login", login);
            httpGet.setHeader("X-Trans-Key", transKey);
            httpGet.setHeader("Content-Type", "application/json");
            httpGet.setHeader("Authorization", "V2-HMAC-SHA256, Signature: " + signature);

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                // Read the response
                BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBuilder.append(line);
                }

                // Print the response
                System.out.println("Get payout request successful!");
                System.out.println("Response: " + responseBuilder.toString());

                // The response will include:
                // - status_description: e.g., "Completed", "Rejected"
                // - status_code: numeric status code
                // - payout_id: the dLocal payout ID
                // - amount: the payout amount
                // - currency: the currency code
                // - creation_date: when the payout was created
                // - country: country code
                // - beneficiary details
                // - amount details including fees and exchange rates
            }

        } catch (Exception e) {
            System.err.println("Get payout request failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 