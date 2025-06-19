<!-- prettier-ignore-start -->

<p align="center">
  <img src="https://raw.githubusercontent.com/yourusername/file-sorter/master/docs/logo.png" alt="FileSorter Logo" width="200"/>
</p>

<h1 align="center">📁 FileSorter</h1>
<p align="center">
  <strong>A smart, configurable, and extensible file-organizer for your life.</strong>
</p>
---

> "Automate your chaos. Sort your life." 🙌

🚧 This project is a work in progress! Features and configuration may change. Use with caution. 🚧

## 🚀 Why FileSorter?

* **Save time**: No more manually dragging files.
* **Stay organized**: Always know where your files live.
* **Fully customize**: Rules that follow **your** way of working.

---

## 🗂️ Table of Contents

1. [Features](#-features)
2. [Getting Started](#-getting-started)
3. [Configuration](#-configuration)
4. [Usage](#-usage)
5. [Logging](#-logging)
6. [Extend It](#-extend-it)
7. [License](#-license)

---

## ✨ Features

* 🎯 **Rule-Driven**: Define file patterns or metadata to match.
* 🗜️ **Archive Support**: ZIP, TAR, GZ, 7Z, RAR—auto-extract & sort.
* 📸 **Metadata Magic**: EXIF for images, ID3 for audio.
* 📆 **Dynamic Folders**: Use `{YYYY}`, `{MM}`, `{DD}`, `{file_type}`, `{filename}`.
* 🤝 **Interactive Duplicates**: Skip, rename, or overwrite with a prompt.
* 📋 **Detailed Logs**: Audit everything, troubleshoot easily.
* 🧩 **Plugin-Friendly**: Add custom handlers for SFTP, cloud, NAS, etc.

---

## 🏁 Getting Started

### Prerequisites

* **Python**: ≥ 3.8
* **PIP packages**:

  ```bash
  pip install mutagen py7zr rarfile
  ```
* **Optional** (for full power):

  * `exiftool` for image metadata
  * `unrar` for RAR archives

### Installation

```bash
git clone https://github.com/kenzo1997/file-sorter.git
cd file-sorter
pip install -r requirements.txt
```

---

## ⚙️ Configuration

Create a `rule.json` in the project root:

```json
{
  "source_path": "~/Downloads",
  "default_destination": "~/Documents/Unmatched",
  "mappings": [
    {
      "include": ["jpg", "jpeg", "png", "gif"],
      "exclude": ["*_tmp.*"],
      "metadata": {
        "camera_make": { "eq": "Canon" },
        "file_size": { "gte": 5242880 }
      },
      "destinations": [
        {
          "type": "local",
          "path": "~/Pictures",
          "subfolders": "photos/{YYYY}/{MM}/"
        }
      ]
    },
    {
      "include": ["pdf", "docx"],
      "exclude": ["confidential_*"],
      "metadata": {
        "created_date": { "lte": "2025-01-01" }
      },
      "destinations": [
        {
          "type": "local",
          "path": "/reports/{YYYY}/{MM}"
        }
      ]
    },
    {
      "include": [ "vm_*.iso" ],
      "destinations": [
        {
          "type": "local",
          "path": "/home/user/Documents/VMs"
        }
      ]
    }
  ]
}
```

| Field                 | What it does                                       |
| --------------------- | -------------------------------------------------- |
| `source_path`         | Where to scan (e.g., `~/Downloads`)                |
| `default_destination` | Fallback folder if no rule matches                 |
| `mappings`            | Array of rule objects                              |
| `include`             | Extensions, wildcards, or regex patterns           |
| `exclude`             | Patterns to **skip**                               |
| `metadata`            | EXIF/ID3 key-value filters                         |
| `destinations`        | Handlers + paths + optional `subfolders` and creds |

---

## 🏃 Usage

```bash
python app.py 
```

---

## 📜 Logging

* Default log file: `filesorter.log`.
* Entries include timestamp, source, destination, and errors.
* Customize in `app.py` or plug into your favorite logger.

---

## 🔧 Extend It

1. **Subclass** `FileHandler`:

   ```python
   class SftpHandler(FileHandler):
       def handle(self, src, dst, credentials):
           # upload logic
   ```

2. **Register** in your script:

   ```python
   sorter = FileSorter(config)
   sorter.register_handler("sftp", SftpHandler())
   ```

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

<!-- prettier-ignore-end -->
