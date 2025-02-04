package alert.checkfile.malicious.cdkn.controller;

import org.springframework.scheduling.annotation.Async;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import alert.checkfile.malicious.cdkn.service.FileCheckService;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
public class FileCheckController {
    @Async
    @PostMapping("/Check-File")
    public void checkFile(@RequestBody String json) throws Exception {
        //TODO: process POST request
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(json);
        JsonNode resultNode = rootNode.path("result");
        JsonNode hash = resultNode.path("hash");

        FileCheckService check = new FileCheckService();
        check.checkFileByVirusTotal(hash.asText());
        
    }
    
}
