from __future__ import annotations

import re

from hallu_defense.domain.models import Claim, ClaimExtractionRequest, SourceSpan

SENTENCE_RE = re.compile(r"(?:[^\n.!?]|(?<=\w)\.(?=\w))+(?:[.!?]+|$)", re.MULTILINE)
CONJUNCTION_RE = re.compile(r"\s+(?:and|y|e)\s+", re.IGNORECASE)


class ClaimExtractor:
    def extract(self, request: ClaimExtractionRequest) -> list[Claim]:
        claims: list[Claim] = []
        claim_index = 1

        for match in SENTENCE_RE.finditer(request.message_text):
            sentence = match.group(0).strip(" \t\r\n.!?")
            if not sentence:
                continue
            parts = self._split_atomic_parts(sentence)
            cursor = match.start()
            for part in parts:
                text = part.strip(" ,;:")
                if not self._looks_like_claim(text):
                    continue
                start = request.message_text.find(text, cursor)
                if start < 0:
                    start = match.start()
                end = start + len(text)
                claims.append(
                    Claim(
                        claim_id=f"clm_{claim_index:04d}",
                        text=text,
                        canonical_form=text.lower(),
                        source_span=SourceSpan(
                            message_id=request.message_id,
                            start_char=start,
                            end_char=end,
                        ),
                    )
                )
                cursor = end
                claim_index += 1

        return claims

    def _split_atomic_parts(self, sentence: str) -> list[str]:
        semicolon_parts = [part.strip() for part in re.split(r";|\n", sentence) if part.strip()]
        atomic: list[str] = []
        for part in semicolon_parts:
            if len(part) > 140:
                atomic.extend(CONJUNCTION_RE.split(part))
            else:
                atomic.append(part)
        return atomic

    def _looks_like_claim(self, text: str) -> bool:
        words = text.split()
        if len(words) < 3:
            return False
        lower = text.lower()
        if lower.startswith(("hola", "gracias", "por favor")):
            return False
        return True
