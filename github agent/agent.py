
import os
import subprocess
import argparse

def run_command(command):
    """Runs a shell command and prints the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Error:", result.stderr)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        print("Stderr:", e.stderr)
        print("Stdout:", e.stdout)

def main():
    parser = argparse.ArgumentParser(description="A GitHub agent to push changes to a repository.")
    parser.add_argument("commit_message", help="The commit message.")
    args = parser.parse_args()

    # 1. Stage all files
    print("Staging files...")
    run_command("git add .")

    # 2. Commit the changes
    print("Committing changes...")
    run_command(f'git commit -m "{args.commit_message}"')

    # 3. Push the changes
    print("Pushing to remote...")
    run_command("git push --set-upstream origin master")

if __name__ == "__main__":
    main()
