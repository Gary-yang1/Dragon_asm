package baiyan

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrConfigGenerated is returned when config/ templates were freshly created.
// The caller should exit cleanly so the user can fill in their keys.
var ErrConfigGenerated = errors.New("config/ 模板已生成，请填写密钥后重新运行")

//go:embed lib
var embeddedLibFS embed.FS

//go:embed config_templates/*
var configTemplatesFS embed.FS

// binaryPaths lists all executable files under lib/ that need 0755 permission.
var binaryPaths = map[string]bool{
	"lib/masscan/masscan":    true,
	"lib/subfinder/subfinder": true,
	"lib/ob/observer_ward":   true,
	"lib/dirscan/dirscan":    true,
}

// ensureLib guarantees that <rootDir>/lib/ exists with all embedded files.
// If lib/ already exists on disk (development), it returns immediately.
func ensureLib(rootDir string) error {
	libDir := filepath.Join(rootDir, "lib")
	if info, err := os.Stat(libDir); err == nil && info.IsDir() {
		return nil
	}
	return extractEmbeddedLib(rootDir)
}

// extractEmbeddedLib writes the embedded lib/ tree to disk under rootDir.
func extractEmbeddedLib(rootDir string) error {
	return fs.WalkDir(embeddedLibFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		targetPath := filepath.Join(rootDir, path)

		if d.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		data, err := embeddedLibFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取嵌入文件 %s 失败: %w", path, err)
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %w", filepath.Dir(targetPath), err)
		}

		mode := os.FileMode(0644)
		if binaryPaths[path] {
			mode = 0755
		}

		if err := os.WriteFile(targetPath, data, mode); err != nil {
			return fmt.Errorf("写入文件 %s 失败: %w", targetPath, err)
		}
		return nil
	})
}

// ensureConfig guarantees that <rootDir>/config/ exists with template files.
// Returns (true, nil) if templates were freshly created, (false, nil) if config/
// already existed, or (false, error) on failure.
func ensureConfig(rootDir string) (bool, error) {
	configDir := filepath.Join(rootDir, "config")
	if info, err := os.Stat(configDir); err == nil && info.IsDir() {
		return false, nil
	}
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return false, err
	}
	for _, name := range []string{"spaceConfig.ini", "subfinder-config.yaml"} {
		data, err := configTemplatesFS.ReadFile("config_templates/" + name)
		if err != nil {
			return false, fmt.Errorf("读取嵌入模板 %s 失败: %w", name, err)
		}
		targetPath := filepath.Join(configDir, name)
		if err := os.WriteFile(targetPath, data, 0644); err != nil {
			return false, fmt.Errorf("写入 %s 失败: %w", targetPath, err)
		}
	}
	return true, nil
}
