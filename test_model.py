from llama_cpp import Llama

llm = Llama(
    model_path="models/Qwen3.5-0.8B-Q4_K_M.gguf",
    n_ctx=2048,
    n_threads=2,
    verbose=False,
)

out = llm.create_chat_completion(
    messages=[{"role": "user", "content": "Say hello in one short sentence."}],
    max_tokens=300,
)
print(repr(out["choices"][0]["message"]["content"]))
print("Finish reason:", out["choices"][0]["finish_reason"])