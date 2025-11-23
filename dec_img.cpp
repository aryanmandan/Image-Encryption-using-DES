#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include "des.cpp"
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
using namespace std;

string pickFile(){
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
    system(command.c_str());
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
    cerr << "No graphical picker implemented on this platform. Please enter the image path: ";
    string manual;
    getline(cin >> ws, manual);
    return manual;
#endif
}
int main(int argc, char* argv[]) {
    string file;

    if (argc < 2) {
        file = pickFile();
        if (file.empty()) {
            cerr << "No file provided. Exiting.\n";
            return 1;
        }
    } else {
        file = argv[1];
    }
    const char* encImg = file.c_str();
    const char* decImg = "img_dec_out.png";
    int width = 0, height = 0, channels_in_file = 0;
    unsigned char* data = stbi_load(encImg, &width, &height, &channels_in_file, 3);
    if (!data) {
        cerr << "Failed to load encrypted PNG: " << encImg << "\n";
        return 1;
    }
    const int channels = 3;
    const int expectedSize = width * height * channels;

    cout << "Loaded encrypted image: " << width << "x" << height
         << " channels=" << channels << " bytes=" << expectedSize << "\n";
    string keyStr;
    cout << "Enter decryption key (will be padded/truncated to 8 bytes): ";
    getline(cin >> ws, keyStr);
    if (keyStr.size() < 8) keyStr.append(8 - keyStr.size(), '0');
    if (keyStr.size() > 8) keyStr.resize(8);
    string ciphertext(reinterpret_cast<char*>(data), static_cast<size_t>(expectedSize));
    stbi_image_free(data);
    DES des;
    string plaintext;
    try {
        plaintext = des.CBC_CTS_decrypt(ciphertext, keyStr);
    }
    catch (const exception& e) {
        cerr << "Decryption error: " << e.what() << "\n";
        return 1;
    }
    if (plaintext.size() != static_cast<size_t>(expectedSize)) {
        cerr << "Warning: decrypted size (" << plaintext.size()
             << ") differs from expected image bytes (" << expectedSize << ").\n";
    }
    vector<unsigned char> out(expectedSize);
    size_t copyLen = min(plaintext.size(), out.size());
    copy(reinterpret_cast<const unsigned char*>(plaintext.data()),
         reinterpret_cast<const unsigned char*>(plaintext.data()) + copyLen,
         out.begin());
    if (copyLen < out.size())
        fill(out.begin() + copyLen, out.end(), 0);

    if (!stbi_write_png(decImg, width, height, channels, out.data(), width * channels)) {
        cerr << "Failed to write decrypted PNG\n";
        return 1;
    }
    cout << "Decryption complete! Output: " << decImg << "\n";
    return 0;
}