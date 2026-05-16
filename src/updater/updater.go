package main

import (
	"C"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const version = "1.0.0"

type UpdateInfo struct {
	Version     string `json:"version"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	Timestamp   int64  `json:"timestamp"`
	Description string `json:"description"`
}

type SignatureUpdate struct {
	Version     string `json:"version"`
	URL         string `json:"url"`
	Count       int    `json:"count"`
	SHA256      string `json:"sha256"`
	Timestamp   int64  `json:"timestamp"`
}

type UpdateStatus struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	Version      string `json:"version"`
	Downloaded   int64  `json:"downloaded"`
	Verified     bool   `json:"verified"`
	LastCheck    int64  `json:"last_check"`
}

var (
	lastCheckTime int64
	updateStatus  UpdateStatus
)

func init() {
	updateStatus.Success = true
	updateStatus.Version = version
}

func setStatus(success bool, message string, downloaded int64, verified bool) {
	updateStatus.Success = success
	updateStatus.Message = message
	updateStatus.Downloaded = downloaded
	updateStatus.Verified = verified
	updateStatus.LastCheck = time.Now().Unix()
}

//export GetUpdaterVersion
func GetUpdaterVersion() *C.char {
	return C.CString(version)
}

//export CheckForUpdates
func CheckForUpdates(updateURL *C.char) *C.char {
	url := C.GoString(updateURL)
	if url == "" {
		url = "http://localhost/update_info.json"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		setStatus(false, fmt.Sprintf("Network error: %v", err), 0, false)
		return C.CString(`{"success": false, "message": "Network error"}`)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		setStatus(false, fmt.Sprintf("HTTP error: %d", resp.StatusCode), 0, false)
		return C.CString(fmt.Sprintf(`{"success": false, "message": "HTTP %d"}`, resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		setStatus(false, "Failed to read response", 0, false)
		return C.CString(`{"success": false, "message": "Read error"}`)
	}

	var info UpdateInfo
	if err := json.Unmarshal(body, &info); err != nil {
		setStatus(false, "Invalid update info format", 0, false)
		return C.CString(`{"success": false, "message": "Invalid format"}`)
	}

	result := fmt.Sprintf(`{"success": true, "version": "%s", "description": "%s"}`, info.Version, info.Description)
	return C.CString(result)
}

//export DownloadSignatures
func DownloadSignatures(signURL *C.char, destPath *C.char, expectedHash *C.char) *C.char {
	url := C.GoString(signURL)
	dest := C.GoString(destPath)
	expected := C.GoString(expectedHash)

	if url == "" {
		url = "http://localhost/signatures.txt"
	}
	if dest == "" {
		execPath, _ := os.Executable()
		dest = filepath.Join(filepath.Dir(execPath), "data", "signatures", "signatures_new.txt")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		setStatus(false, fmt.Sprintf("Download failed: %v", err), 0, false)
		return C.CString(`{"success": false, "message": "Download failed"}`)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		setStatus(false, fmt.Sprintf("HTTP %d", resp.StatusCode), 0, false)
		return C.CString(fmt.Sprintf(`{"success": false, "message": "HTTP %d"}`, resp.StatusCode))
	}

	os.MkdirAll(filepath.Dir(dest), 0755)
	file, err := os.Create(dest)
	if err != nil {
		setStatus(false, fmt.Sprintf("Cannot create file: %v", err), 0, false)
		return C.CString(`{"success": false, "message": "File error"}`)
	}
	defer file.Close()

	downloaded, err := io.Copy(file, resp.Body)
	if err != nil {
		setStatus(false, fmt.Sprintf("Write error: %v", err), 0, false)
		return C.CString(`{"success": false, "message": "Write error"}`)
	}

	file.Sync()

	verified := false
	if expected != "" {
		hash, err := computeFileHash(dest)
		if err == nil && strings.EqualFold(hash, expected) {
			verified = true
		}
	}

	setStatus(true, "Download complete", downloaded, verified)

	if verified {
		oldPath := dest + ".old"
		newPath := dest
		if _, err := os.Stat(strings.TrimSuffix(dest, "_new.txt") + ".txt"); err == nil {
			os.Rename(strings.TrimSuffix(dest, "_new.txt") + ".txt", oldPath)
		}
		os.Rename(newPath, strings.TrimSuffix(dest, "_new.txt")+".txt")
		if _, err := os.Stat(oldPath); err == nil {
			os.Remove(oldPath)
		}
		return C.CString(`{"success": true, "message": "Updated and verified", "verified": true}`)
	}

	return C.CString(fmt.Sprintf(`{"success": true, "message": "Downloaded %d bytes", "verified": false}`, downloaded))
}

//export GetUpdateStatus
func GetUpdateStatus() *C.char {
	data, _ := json.Marshal(updateStatus)
	return C.CString(string(data))
}

//export SetUpdateURL
func SetUpdateURL(url *C.char) {
	_ = C.GoString(url)
}

//export GetLastCheckTime
func GetLastCheckTime() int64 {
	return lastCheckTime
}

func computeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

//export VerifySignature
func VerifySignature(filePath *C.char, expectedHash *C.char) int {
	path := C.GoString(filePath)
	hash := C.GoString(expectedHash)

	if path == "" || hash == "" {
		return 0
	}

	actualHash, err := computeFileHash(path)
	if err != nil {
		return 0
	}

	if strings.EqualFold(actualHash, hash) {
		return 1
	}
	return 0
}

//export DownloadComponent
func DownloadComponent(url *C.char, destPath *C.char, verifyHash *C.char) *C.char {
	downloadURL := C.GoString(url)
	dest := C.GoString(destPath)
	hash := C.GoString(verifyHash)

	if downloadURL == "" || dest == "" {
		return C.CString(`{"success": false, "message": "Invalid parameters"}`)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"success": false, "message": "%v"}`, err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return C.CString(fmt.Sprintf(`{"success": false, "message": "HTTP %d"}`, resp.StatusCode))
	}

	os.MkdirAll(filepath.Dir(dest), 0755)
	file, err := os.Create(dest)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"success": false, "message": "%v"}`, err))
	}
	defer file.Close()

	downloaded, err := io.Copy(file, resp.Body)
	if err != nil {
		return C.CString(fmt.Sprintf(`{"success": false, "message": "%v"}`, err))
	}

	verified := false
	if hash != "" {
		actualHash, _ := computeFileHash(dest)
		if strings.EqualFold(actualHash, hash) {
			verified = true
		}
	}

	return C.CString(fmt.Sprintf(`{"success": true, "verified": %v, "size": %d}`, verified, downloaded))
}

func main() {}