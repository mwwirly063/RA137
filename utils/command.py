import subprocess
from pathlib import Path


def run_command(
    cmd,
    output_file=None,
    timeout=10000,
    silent=True
):
    """
    Run shell command safely.

    Args:
        cmd (str): command to execute
        output_file (str): optional output file
        timeout (int): timeout in seconds
        silent (bool): suppress stderr/stdout

    Returns:
        tuple(bool, str):
            success status,
            stdout/error message
    """

    try:

        stdout_target = subprocess.PIPE
        stderr_target = subprocess.PIPE

        # Save output to file
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:

                result = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.PIPE if not silent else subprocess.DEVNULL,
                    text=True,
                    timeout=timeout
                )

        else:

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

        if result.returncode != 0:

            error_msg = result.stderr.strip() if result.stderr else "Unknown error"

            print(f"[ERROR] Command failed: {cmd}")
            print(f"[ERROR] {error_msg}")

            return False, error_msg

        return True, result.stdout if not output_file else ""

    except subprocess.TimeoutExpired:

        print(f"[TIMEOUT] {cmd}")
        return False, "Timeout"

    except Exception as e:

        print(f"[EXCEPTION] {e}")
        return False, str(e)