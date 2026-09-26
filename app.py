"""Streamlit UI for the Acme Support Ticket Operator.

Run: streamlit run app.py
"""

import logging
import os

import streamlit as st
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

import graph  # noqa: E402  (after logging/env setup)
from config.constants import DEFAULT_MODELS, SAMPLE_TICKET  # noqa: E402
from llm import resolve_model_name  # noqa: E402

st.set_page_config(page_title="Acme Support Operator")
st.title("Acme Support Ticket Operator")

with st.sidebar:
    st.header("Models (OpenRouter)")
    st.caption("Switch to a non-approved / disallowed model to exercise AI_APP_SEC_006 / 028.")
    overrides = {agent: st.text_input(f"{agent} model", resolve_model_name(agent)) for agent in DEFAULT_MODELS}

ticket_text = st.text_area("Ticket", SAMPLE_TICKET, height=150)

if st.button("Submit", type="primary") and ticket_text.strip():
    if not os.getenv("OPENROUTER_API_KEY"):
        st.error("OPENROUTER_API_KEY is not set (see .env.example).")
        st.stop()

    with st.spinner("Agents working..."):
        result = graph.run_ticket(ticket_text, overrides)

    col1, col2 = st.columns(2)
    col1.metric("Category", result["category"])
    col2.metric("Priority", result["priority"])
    st.write("**Models used:**", result["models_used"])

    # [AI_DAT_SEC_012] Mask PII on user interfaces — UNGUARDED: the ticket and the
    # agent reply are rendered as-is, so SSN / email / phone / card are visible.
    st.subheader("Ticket")
    st.write(result["ticket_text"])
    st.subheader("Agent reply")
    st.write(result["reply"])
