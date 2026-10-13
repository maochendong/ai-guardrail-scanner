package example;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

// The Spring AI version and external gateway enforcement are not supplied.
class UnknownController {
    private ChatClient chatClient;

    @PostMapping("/ask")
    String ask(@RequestBody String prompt) {
        return chatClient.prompt().system(prompt).call().content();
    }
}
