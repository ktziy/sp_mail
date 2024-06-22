package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "crypto/rc4"
    "encoding/hex"
    "fmt"
    "os"
    "strconv"
    "strings"
)

func rc4EncryptDecrypt(key, text string, encode bool) (string, error) {
    cipher, err := rc4.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    data := []byte(text)
    if !encode {
        data, err = hex.DecodeString(text)
        if err != nil {
            return "", err
        }
    }
    cipher.XORKeyStream(data, data)
    if encode {
        return hex.EncodeToString(data), nil
    }
    return string(data), nil
}

func aesEncrypt(key, text string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    ciphertext := make([]byte, aes.BlockSize+len(text))
    iv := ciphertext[:aes.BlockSize]
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
    return hex.EncodeToString(ciphertext), nil
}

func aesDecrypt(key, text string) (string, error) {
    data, err := hex.DecodeString(text)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    if len(data) < aes.BlockSize {
        return "", fmt.Errorf("ciphertext too short")
    }
    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(data, data)
    return string(data), nil
}

func md5Hash(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

func main() {
    if len(os.Args) < 4 {
        fmt.Println("Usage: myapp <e|d> <text> [-n] [password] [word1 num1] [word2 num2] ...")
        return
    }

    action := os.Args[1]
    text := os.Args[2]
    var password string
    var args []string
    var key strings.Builder

    if os.Args[3] == "-n" {
        args = os.Args[4:]
    } else {
        password = os.Args[3]
        key.WriteString(password)
        args = os.Args[4:]
    }

    if len(args)%2 != 0 {
        fmt.Println("Error: Word and number pairs are not balanced.")
        return
    }

    for i := 0; i < len(args); i += 2 {
        word := args[i]
        num, err := strconv.Atoi(args[i+1])
        if err != nil {
            fmt.Printf("Error: Invalid number '%s'.\n", args[i+1])
            return
        }
        for j := 0; j < num; j++ {
            key.WriteString(word)
        }
    }

    keyString := key.String()
    md5Key := md5Hash(keyString)

    switch action {
    case "e":
        // Step 1: RC4 encryption
        rc4Encrypted, err := rc4EncryptDecrypt(keyString, text, true)
        if err != nil {
            fmt.Println("Error during RC4 encryption:", err)
            return
        }

        // Step 2: AES encryption of the RC4 encrypted text
        aesEncrypted, err := aesEncrypt(md5Key, rc4Encrypted)
        if err != nil {
            fmt.Println("Error during AES encryption:", err)
            return
        }

        fmt.Println("Encrypted text:", aesEncrypted)

    case "d":
        // Step 1: AES decryption
        aesDecrypted, err := aesDecrypt(md5Key, text)
        if err != nil {
            fmt.Println("Error during AES decryption:", err)
            return
        }

        // Step 2: RC4 decryption of the AES decrypted text
        rc4Decrypted, err := rc4EncryptDecrypt(keyString, aesDecrypted, false)
        if err != nil {
            fmt.Println("Error during RC4 decryption:", err)
            return
        }

        fmt.Println("Decrypted text:", rc4Decrypted)

    default:
        fmt.Println("Invalid action. Use 'e' for encode or 'd' for decode.")
    }
}
