BLUE_BG = "\033[44m"
WHITE_BOLD = "\033[1m\033[37m"
WHITE_ON_BLUE_BG = "\033[1m\033[47m\033[34m"
RESET = "\033[0m"

BANNER_TEXT = """LUDI
UNIFIES
DECOMPILER
INTERFACES"""

TITLE = "LUDI Unifies Decompiler Interface"


def get_banner() -> str:
    text_lines = BANNER_TEXT.strip().split("\n")
    max_width = max(len(line) for line in text_lines)
    width = max_width + 4  # 2 spaces padding on each side

    lines = []
    lines.append(f"{BLUE_BG}{WHITE_BOLD}{' ' * width}{RESET}")

    for line in text_lines:
        padded_line = f"  {line.ljust(max_width)}  "
        first_letter_pos = next(
            (i for i, c in enumerate(padded_line) if c.isalpha()), None
        )
        if first_letter_pos is not None:
            colored_line = (
                f"{BLUE_BG}{WHITE_BOLD}{padded_line[:first_letter_pos]}{RESET}"
                f"{WHITE_ON_BLUE_BG}{padded_line[first_letter_pos]}{RESET}"
                f"{BLUE_BG}{WHITE_BOLD}{padded_line[first_letter_pos+1:]}{RESET}"
            )
        else:
            colored_line = f"{BLUE_BG}{WHITE_BOLD}{padded_line}{RESET}"
        lines.append(colored_line)

    lines.append(f"{BLUE_BG}{WHITE_BOLD}{' ' * width}{RESET}")

    return "\n".join(lines)


def get_title() -> str:
    return TITLE
