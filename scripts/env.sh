# Load with:  source scripts/env.sh   (settings last until you log out)
export SHIELD_BACKEND=llm
export LOOP_LLM_BASE_URL=http://127.0.0.1:8080/v1     # attacker in the loop: Granite 2B
export REWRITE_LLM_BASE_URL=http://127.0.0.1:8080/v1  # rewriter: also 2B (the 1B wrote poor rewrites)
export EVAL_LLM_BASE_URL=http://127.0.0.1:8080/v1     # evaluation attacker: 2B
export SHIELD_MAX_ROUNDS=3
echo "Loaded: attacker, rewriter and evaluation all on Granite 2B (:8080)"
