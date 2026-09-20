"""Entity-specific discovery query strategies; discovery never becomes evidence by itself."""

from osint_lab.graph.models import GraphEntityType


class DiscoveryQueryEngine:
    def queries(self, entity_type: GraphEntityType, value: str) -> tuple[str, ...]:
        if not isinstance(entity_type, GraphEntityType) or not isinstance(value, str) or not value.strip():
            raise ValueError("valid entity type and value are required")
        quoted = f'"{value.strip()}"'
        strategies = {
            GraphEntityType.PHONE: (quoted, f"{quoted} kontakt", f"{quoted} filetype:pdf"),
            GraphEntityType.EMAIL: (quoted, f"{quoted} contact", f"{quoted} filetype:pdf"),
            GraphEntityType.USERNAME: (quoted, f"{quoted} profile"),
            GraphEntityType.DOMAIN: (f"site:{value.strip()}", f'"{value.strip()}" filetype:pdf'),
            GraphEntityType.COMPANY: (quoted, f"{quoted} kontakt", f"{quoted} filetype:pdf"),
        }
        return strategies.get(entity_type, (quoted,))
