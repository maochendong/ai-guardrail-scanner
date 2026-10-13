package example;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import reactor.core.publisher.Flux;

// Corrects specific unsafe example patterns. Other controls still need evidence.
class CorrectedController {
    private ChatClient chatClient;

    @PostMapping("/ask")
    String ask(@RequestBody String prompt) {
        return chatClient.prompt().system("Answer the user's question using the configured policy.")
                .user(prompt).call().content();
    }

    @PostMapping("/stream")
    Flux<String> stream(@RequestBody String prompt) {
        return chatClient.prompt().user(prompt).stream().content().retry(2);
    }
}
