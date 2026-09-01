# app/repository/metadata.py

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RepositoryMetadata:
    """
    Metadata describing a repository loaded into Vajra.
    """

    workspace_id: str

    total_files: int = 0

    source_files: int = 0

    languages: Dict[str, int] = field(default_factory=dict)

    files: List[dict] = field(default_factory=list)

    def add_file(self, file_info: dict):
        """
        Add one discovered file to the repository metadata.
        """

        self.files.append(file_info)

        self.total_files += 1

        language = file_info.get("language", "Unknown")

        # Count recognized source languages.
        if language != "Unknown":
            self.source_files += 1

        self.languages[language] = (
            self.languages.get(language, 0) + 1
        )

    def to_dict(self):
        """
        Convert metadata into a normal dictionary.
        """

        return {
            "workspace_id": self.workspace_id,
            "total_files": self.total_files,
            "source_files": self.source_files,
            "languages": self.languages,
            "files": self.files,
        }