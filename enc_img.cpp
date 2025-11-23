#include <fstream>
#include <vector>
#include <cstdint>
#include <iostream>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include "des.cpp"
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
using namespace std;

string pickFile() {
#ifdef _WIN32
    const char* tempEnv = getenv("TEMP");
    string tempDir = tempEnv ? tempEnv : "C:\\Windows\\Temp";

    string tempFile = tempDir + "\\filedialog_result.txt";

    string psPath = tempFile;
    for (size_t i = 0; i + 1 <= psPath.size(); ++i) {
        if (psPath[i] == '\\') {
            psPath.insert(i, "\\");
            ++i;
        }
    }

    string command =
        "powershell -NoProfile -Command \"Add-Type -AssemblyName System.Windows.Forms; "
        "$f = New-Object System.Windows.Forms.OpenFileDialog; "
        "$f.Filter = 'Image Files|*.png;*.jpg;*.jpeg;*.bmp;*.tiff|All files|*.*'; "
        "if($f.ShowDialog() -eq 'OK'){ [System.IO.File]::WriteAllText('" + psPath + "',$f.FileName) }\"";

    int rc = system(command.c_str());
    (void)rc;

    FILE* fp = fopen(tempFile.c_str(), "r");
    if (!fp) {
        cerr << "File picker failed or was cancelled. Please enter the image path manually: ";
        string manual;
        getline(cin >> ws, manual);
        return manual;
    }

    char buffer[8192];
    if (!fgets(buffer, sizeof(buffer), fp)) {
        fclose(fp);
        cerr << "Failed to read picker result. Please enter the image path manually: ";
        string manual;
        getline(cin >> ws, manual);
        return manual;
    }

    fclose(fp);

    string path(buffer);
    while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
        path.pop_back();

    return path;

#else
    string tempFile = "/tmp/filedialog_result.txt";

    string command =
        "osascript -e 'set theFile to choose file' "
        "-e 'do shell script \"echo \" & quoted form of POSIX path of theFile & \" > " + tempFile + "\"'";

    int rc = system(command.c_str());
    (void)rc;

    FILE* fp = fopen(tempFile.c_str(), "r");
    if (!fp) {
        cerr << "File picker failed or was cancelled. Please enter the image path manually: ";
        string manual;
        getline(cin >> ws, manual);
        return manual;
    }

    char buffer[8192];
    if (!fgets(buffer, sizeof(buffer), fp)) {
        fclose(fp);
        cerr << "Failed to read picker result. Please enter the image path manually: ";
        string manual;
        getline(cin >> ws, manual);
        return manual;
    }

    fclose(fp);

    string path(buffer);
    while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
        path.pop_back();

    return path;
#endif
}

int main() {
    string file = pickFile();
    if (file.empty()) {
        cerr << "No file chosen or picker failed.\n";
        return 1;
    }

    int width = 0, height = 0, channels_in_file = 0;
    unsigned char* data = stbi_load(file.c_str(), &width, &height, &channels_in_file, 3);

    if (!data) {
        cerr << "Failed to load image: " << file << '\n';
        return 1;
    }

    const int channels = 3;
    const size_t size = (size_t)width * (size_t)height * channels;

    cout << "Loaded: " << file << " (" << width << "x" << height
         << "), channels=" << channels << ", bytes=" << size << "\n";

    string keyStr;
    cout << "Enter encryption key (exactly 8 chars; will be padded/truncated): ";
    cin >> keyStr;

    if (keyStr.size() < 8)
        keyStr.append(8 - keyStr.size(), '0');
    else if (keyStr.size() > 8)
        keyStr = keyStr.substr(0, 8);

    string imgBytes(reinterpret_cast<char*>(data), size);

    DES a;
    string cipher = a.CBC_CTS_encrypt(imgBytes, keyStr);

    if (cipher.size() != size) {
        cerr << "Warning: encrypted data size (" << cipher.size()
             << ") != original size (" << size << ")\n";
    }

    vector<unsigned char> encrypted(
        reinterpret_cast<const unsigned char*>(cipher.data()),
        reinterpret_cast<const unsigned char*>(cipher.data() + cipher.size())
    );

    stbi_image_free(data);

    const char* outPath = "img_enc.png";

    if (!stbi_write_png(outPath, width, height, channels, encrypted.data(), width * channels)) {
        cerr << "Failed to write encrypted PNG: " << outPath << '\n';
        return 1;
    }

    cout << "Encrypted PNG written: " << outPath << '\n';
    return 0;
}
