package alert.checkfile.malicious.cdkn.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class FileCheckService {
    private static final String apiUrl = "https://www.virustotal.com/api/v3/files/";
    private static final String apiKey = "API_KEY_VirusTotal";
    
    public void checkFileByVirusTotal(String hashFromSiem, String pathFromSiem, String userFromSiem) throws Exception {
        //Tạo rest template để gửi request
        RestTemplate restTemplate = new RestTemplate();
        String url = apiUrl + hashFromSiem;
       
        //Tạo header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Accept", "application/json");
        headers.add("X-Apikey", "da4b2918878e460916ff948f3fcd4a9cab86477dd600621950568d24f1c0764d");

        //Gửi request và nhận phản hồi
        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

            //Kiểm tra xem kết quả trả về có thành công không
            if (response.getStatusCode() == HttpStatus.OK) {
                //Parse response JSON
                ObjectMapper mapper = new ObjectMapper();
                JsonNode rootNode = mapper.readTree(response.getBody());
                JsonNode lastAnalysisStats = rootNode.path("data")
                                                     .path("attributes")
                                                     .path("last_analysis_stats");
                int malicious = lastAnalysisStats.path("malicious").asInt();
                int score = malicious;

                //Cảnh báo nếu score lớn hơn 1, tức là có trên 1 bên đánh giá của virus total đánh giá đây là độc hại
                if (score > 1) {
                    String message = "<b>☣️ SPLUNK ALERT MALICIOUS FILE ☣️</b>\n\n"
                    + "Detect a malicious file has been created" + "\n\n"
                    + "<b>PATH:</b> " + pathFromSiem + "\n"
                    + "<b>HASH:</b> " + hashFromSiem + "\n"
                    + "<b>USER:</b> " + userFromSiem +"\n"
                    + "<b>SCORE:</b> " + score + "\n\n"
                    + "Please check!";
                    sendMessage(message);
                }
            } else {
                System.out.println("Failed to fetch data from VirusTotal. Status: " + response.getStatusCode());
            }
        } catch (Exception e) {
            // TODO: handle exception
            throw new Exception("Error while checking file with VirusTotal: " + e.getMessage());
        }
    }

    public static void sendMessage(String message) throws Exception {
        String botToken = "Bot_Token";
        String chatID = "Chat_ID";
        String teleApiUrl = "https://api.telegram.org/bot" + botToken + "/sendMessage";
    
        RestTemplate restTemplate = new RestTemplate();
          
        // Tạo body request dưới dạng JSON
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("chat_id", chatID);
        requestBody.put("text", message);
        requestBody.put("parse_mode", "HTML"); // cho mark down để viết đậm
        // Gửi request POST lên api của tele
        restTemplate.postForObject(teleApiUrl, requestBody, String.class);


    }
}
