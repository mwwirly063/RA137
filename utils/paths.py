from pathlib import Path


def create_target_output(target):

    target = target.replace("https://", "")
    target = target.replace("http://", "")
    target = target.replace("/", "_")

    target_dir = Path("outputs") / target

    target_dir.mkdir(parents=True, exist_ok=True)

    return target_dir