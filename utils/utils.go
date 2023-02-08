package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const ExtensionPNG = ".png"

// CopyDir copies a directory to the specified dest dir using the cp command.
func CopyDir(src, dest string) error {
	cmdName := "cp"
	cmdArgs := []string{"-r", src, dest}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = os.Environ()
	_, err := cmd.CombinedOutput()
	return err
}

func GenerateLocalFile(body []byte, proxy, bucket, folder, localTempDir, filename, extension string) (string, error) {
	if filename == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return "", err
		}

		filename = u.String()
	}
	path := filepath.Join(localTempDir, filename+extension)
	err := os.WriteFile(path, body, 0600)
	if err != nil {
		return "", err
	}

	if proxy == "" {
		return filepath.Join(localTempDir, filename+extension), nil
	}

	if bucket == "" {
		return filename + extension, nil
	}

	if strings.Contains(bucket, "public") {
		return fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucket, filepath.Join(folder, filename+extension)), nil
	}
	return fmt.Sprintf("%s/%s", proxy, filepath.Join(folder, filename+extension)), nil
}
