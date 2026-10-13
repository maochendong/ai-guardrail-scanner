package example;

import org.slf4j.Logger;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor;
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import reactor.core.publisher.Flux;

// Static-analysis demonstration only. Do not deploy these patterns.
class UnsafeController {
    private ChatClient chatClient;
    private ChatMemory memory;
    private Logger logger;

    @PostMapping("/ask")
    String ask(@RequestBody String prompt) {
        String answer = chatClient.prompt()
                .system(prompt)
                .advisors(MessageChatMemoryAdvisor.builder(memory).build())
                .advisors(a -> a.param(ChatMemory.CONVERSATION_ID, "shared-example-session"))
                .call().content();
        logger.info(answer);
        return answer;
    }

    @PostMapping("/stream")
    Flux<String> stream(@RequestBody String prompt) {
        return chatClient.prompt().user(prompt).stream().content().retry();
    }
}
