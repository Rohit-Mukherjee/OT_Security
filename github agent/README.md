# GitHub Agent

This script helps you push all files in the current directory to a GitHub repository.

## How to Use

1.  **Initialize a Git repository:**

    If you haven't already, initialize a Git repository in your project directory:

    ```bash
    git init
    ```

2.  **Add a remote repository:**

    Add your GitHub repository as a remote:

    ```bash
    git remote add origin <your-repository-url>
    ```

3.  **Run the agent:**

    To stage, commit, and push your changes, run the following command from your project directory:

    ```bash
    python "D:\gemini\github agent\agent.py" "Your commit message"
    ```

## Authentication

This script relies on your local Git configuration for authentication. If you haven't configured Git to store your credentials, you might be prompted for your username and password.

### Using a Personal Access Token (PAT)

For a more secure and convenient authentication method, we recommend using a Personal Access Token (PAT).

1.  **Generate a PAT:**

    -   Go to your GitHub settings: [https://github.com/settings/tokens](https://github.com/settings/tokens)
    -   Click "Generate new token".
    -   Give your token a descriptive name.
    -   Select the `repo` scope to grant full control of private repositories.
    -   Click "Generate token" and copy the token.

2.  **Configure Git to use the PAT:**

    You can use a credential helper to store your PAT. When prompted for your password, paste your PAT.

    For more information, see the official GitHub documentation: [Creating a personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
