def refang(text: str) -> str:
    """
    Basit refang:
    hxxp -> http, hxxps -> https
    [.] -> .
    [@] -> @
    """
    return (
        text.replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
            .replace("[.]", ".")
            .replace("[@]", "@")
    )