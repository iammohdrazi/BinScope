import platform


def detect_os() -> str:
    """Return a string representing the current OS."""
    sysname = platform.system().lower()
    if "windows" in sysname:
        return "windows"
    elif "linux" in sysname:
        return "linux"
    elif "darwin" in sysname:
        return "macos"
    return sysname


def human_size(num_bytes: int) -> str:
    """Convert bytes to a human-readable format."""
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < step:
            return f"{size:.2f} {unit}"
        size /= step
    return f"{size:.2f} PB"
