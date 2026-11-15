package volcengine

import "os"

func credentialFilesFromEnvironment() CredentialFiles {
	return CredentialFiles{
		AccessKeyPath: os.Getenv("VOLCENGINE_ACCESS_KEY_FILE"),
		SecretKeyPath: os.Getenv("VOLCENGINE_SECRET_KEY_FILE"),
	}
}
