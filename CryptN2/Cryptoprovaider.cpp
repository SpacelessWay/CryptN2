#include "Cryptoprovaider.h"
#include "GeneratePublicKey.h"
#include <openssl/bn.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include "Encrypt.h"
#include "Decrypt.h"

namespace CryptN {

    Cryptoprovaider::Cryptoprovaider(void)
    {
        InitializeComponent();
    }

    Cryptoprovaider::~Cryptoprovaider()
    {
        if (components)
        {
            delete components;
        }
    }

    void Cryptoprovaider::InitializeComponent(void)
    {
        this->components = gcnew System::ComponentModel::Container();
        this->Size = System::Drawing::Size(618, 400);
        this->Text = L"���������������";
        this->Padding = System::Windows::Forms::Padding(0);
        this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
        this->BackColor = Color::LightGray;

        // ���������
        this->labelTitle = gcnew System::Windows::Forms::Label();
        this->labelTitle->Text = L"���������������";
        this->labelTitle->Font = gcnew System::Drawing::Font("Arial", 16, FontStyle::Bold);
        this->labelTitle->Location = Point(20, 20);
        this->labelTitle->Size = System::Drawing::Size(560, 30);
        this->Controls->Add(this->labelTitle);

        // ���� ��� ������ ���� � �����
        this->textBoxFilePath = gcnew System::Windows::Forms::TextBox();
        this->textBoxFilePath->Location = Point(20, 70);
        this->textBoxFilePath->Size = System::Drawing::Size(400, 20);
        this->Controls->Add(this->textBoxFilePath);

        // ������ ������ �����
        this->buttonSelectFile = gcnew System::Windows::Forms::Button();
        this->buttonSelectFile->Text = L"������� ����";
        this->buttonSelectFile->Location = Point(430, 68);
        this->buttonSelectFile->Size = System::Drawing::Size(150, 25);
        this->buttonSelectFile->Click += gcnew EventHandler(this, &Cryptoprovaider::SelectFile);
        this->Controls->Add(this->buttonSelectFile);

        // ������� "�������� ����"
        this->labelPublicKey = gcnew System::Windows::Forms::Label();
        this->labelPublicKey->Text = L"�������� ����:";
        this->labelPublicKey->Location = Point(20, 110);
        this->labelPublicKey->Size = System::Drawing::Size(100, 20);
        this->Controls->Add(this->labelPublicKey);

        // ����� ��� N
        this->labelN = gcnew System::Windows::Forms::Label();
        this->labelN->Text = L"N:";
        this->labelN->Location = Point(20, 140);
        this->labelN->Size = System::Drawing::Size(20, 20);
        this->Controls->Add(this->labelN);

        // ���� ��� ������ N
        this->textBoxN = gcnew System::Windows::Forms::TextBox();
        this->textBoxN->Location = Point(45, 140);
        this->textBoxN->Size = System::Drawing::Size(535, 20);
        this->textBoxN->ReadOnly = true;
        this->Controls->Add(this->textBoxN);

        // ����� ��� e
        this->labelE = gcnew System::Windows::Forms::Label();
        this->labelE->Text = L"e:";
        this->labelE->Location = Point(20, 170);
        this->labelE->Size = System::Drawing::Size(20, 20);
        this->Controls->Add(this->labelE);

        // ���� ��� ������ e
        this->textBoxE = gcnew System::Windows::Forms::TextBox();
        this->textBoxE->Location = Point(45, 170);
        this->textBoxE->Size = System::Drawing::Size(535, 20);
        this->textBoxE->ReadOnly = true;
        this->Controls->Add(this->textBoxE);

        // ������ ���������� �����
        this->buttonRefreshKey = gcnew System::Windows::Forms::Button();
        this->buttonRefreshKey->Text = L"�������� ����";
        this->buttonRefreshKey->Location = Point(20, 200);
        this->buttonRefreshKey->Size = System::Drawing::Size(150, 25);
        this->buttonRefreshKey->Click += gcnew EventHandler(this, &Cryptoprovaider::RefreshPublicKey);
        this->Controls->Add(this->buttonRefreshKey);

        // ������ ������ �����
        this->buttonReplaceKey = gcnew System::Windows::Forms::Button();
        this->buttonReplaceKey->Text = L"�������� ����";
        this->buttonReplaceKey->Location = Point(180, 200);
        this->buttonReplaceKey->Size = System::Drawing::Size(150, 25);
        this->buttonReplaceKey->Click += gcnew EventHandler(this, &Cryptoprovaider::ReplacePublicKey);
        this->Controls->Add(this->buttonReplaceKey);

        // ������ "���������"
        this->buttonEncrypt = gcnew System::Windows::Forms::Button();
        this->buttonEncrypt->Text = L"���������";
        this->buttonEncrypt->Location = Point(20, 240);
        this->buttonEncrypt->Size = System::Drawing::Size(150, 25);
        this->buttonEncrypt->Click += gcnew EventHandler(this, &Cryptoprovaider::EncryptFile);
        this->Controls->Add(this->buttonEncrypt);

        // ������ "�����������"
        this->buttonDecrypt = gcnew System::Windows::Forms::Button();
        this->buttonDecrypt->Text = L"�����������";
        this->buttonDecrypt->Location = Point(180, 240);
        this->buttonDecrypt->Size = System::Drawing::Size(150, 25);
        this->buttonDecrypt->Click += gcnew EventHandler(this, &Cryptoprovaider::DecryptFile);
        this->Controls->Add(this->buttonDecrypt);

        // ��������� ���������� ��������� �����
        GeneratePublicKey();
    }

    void Cryptoprovaider::SelectFile(Object^ sender, EventArgs^ e)
    {
        OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
        openFileDialog->Filter = L"All files (*.*)|*.*";
        if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
        {
            this->textBoxFilePath->Text = openFileDialog->FileName;
        }
    }
    std::string marshal_to_std_string(String^ managedString) {
        if (managedString == nullptr) {
            return std::string();
        }

        // �������� ����� ������
        int length = managedString->Length;

        // ������� ����� ��� �������� ��������
        std::vector<char> buffer(length + 1);

        // �������� ������� �� String^ � �����
        for (int i = 0; i < length; ++i) {
            buffer[i] = static_cast<char>(managedString[i]);
        }

        // ��������� ����������� ������� ������
        buffer[length] = '\0';

        // ���������� std::string
        return std::string(&buffer[0]);
    }

    void Cryptoprovaider::GeneratePublicKey(void)
    {
        BIGNUM* N = NULL;
        BIGNUM* e = NULL;
        std::string password;
        if (!LoadPublicKeyFromFile(&N, &e) || !CheckEncryptedKeyFile(password)) {
            password = GenPassword(password);
            generatePublicKey(password, &N, &e);
        }

        char* N_str = BN_bn2dec(N);
        char* e_str = BN_bn2dec(e);

        this->textBoxN->Text = gcnew System::String(N_str);
        this->textBoxE->Text = gcnew System::String(e_str);

        OPENSSL_free(N_str);
        OPENSSL_free(e_str);

        BN_free(N);
        BN_free(e);
    }

    // ������� ��� ���������� ������ �� �������
    std::vector<std::string> split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(s);
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    bool Cryptoprovaider::LoadPublicKeyFromFile(BIGNUM** N, BIGNUM** e) {
        std::ifstream inFile("public_key.txt");
        if (!inFile.is_open()) {
            return false;
        }

        std::string line;
        bool N_found = false;
        bool e_found = false;

        while (std::getline(inFile, line)) {
            std::vector<std::string> parts = split(line, ':');
            if (parts.size() != 2) {
                continue; // ���������� ������, ������� �� ������������� ������� "����:��������"
            }

            if (parts[0] == "N") {
                *N = BN_new();
                if (BN_dec2bn(N, parts[1].c_str()) == 0) {
                    BN_free(*N);
                    inFile.close();
                    return false;
                }
                N_found = true;
            }
            else if (parts[0] == "e") {
                *e = BN_new();
                if (BN_dec2bn(e, parts[1].c_str()) == 0) {
                    BN_free(*e);
                    inFile.close();
                    return false;
                }
                e_found = true;
            }

            if (N_found && e_found) {
                break; // �� ����� ��� ��������, ����� ��������� ������
            }
        }

        inFile.close();
        return N_found && e_found;
    }

    void Cryptoprovaider::RefreshPublicKey(Object^ sender, EventArgs^ e)
    {
        GeneratePublicKey();
    }

    void Cryptoprovaider::ReplacePublicKey(Object^ sender, EventArgs^ e)
    {
        BIGNUM* N = NULL;
        BIGNUM* ei = NULL;
        std::string password;
        GenPassword(password);

        generatePublicKey(password, &N, &ei);

        char* N_str = BN_bn2dec(N);
        char* e_str = BN_bn2dec(ei);

        this->textBoxN->Text = gcnew System::String(N_str);
        this->textBoxE->Text = gcnew System::String(e_str);

        OPENSSL_free(N_str);
        OPENSSL_free(e_str);

        BN_free(N);
        BN_free(ei);
    }

    void Cryptoprovaider::EncryptFile(Object^ sender, EventArgs^ e)
    {
        // ��������, ������ �� ���� � �����
        if (this->textBoxFilePath->Text == "") {
            MessageBox::Show(L"������� ���� ��� ����������", L"������");
            return;
        }
        std::string TofilePath;
        FolderBrowserDialog^ folderBrowserDialog = gcnew FolderBrowserDialog();
        folderBrowserDialog->Description = L"�������� ����� ��� ����������";
        if (folderBrowserDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
        {
            TofilePath = marshal_to_std_string(folderBrowserDialog->SelectedPath);
        }
        else {
            MessageBox::Show(L"������� ����� ��� ����������", L"������");
            return;
        }
        
         // ����� ���� ��� ����� ������
        std::string password;
        password = EnterPassword(password);
        //std::cerr << password << std::endl;
        // ��������, ������ �� ������
        if (password.empty()) {
            MessageBox::Show(L"������� ������ ��� ����������", L"������");
            return;
        }

        

        // �������������� ���� � ����� � std::string
        std::string filePath = marshal_to_std_string(this->textBoxFilePath->Text);
        BIGNUM* N = BN_new();
        BN_dec2bn(&N, marshal_to_std_string(this->textBoxN->Text).c_str());
        BIGNUM* en = BN_new();
        BN_dec2bn(&en, marshal_to_std_string(this->textBoxE->Text).c_str());

        // �������� ������ � Encrypt.cpp
        // �����������, ��� � ��� ���� ������� EncryptFile � Encrypt.cpp, ������� ��������� ���� � ����� � ������
        if (Encrypt(filePath, password, N,en, TofilePath)) {
            MessageBox::Show(L"���� ������� ����������", L"�����");
        }
        else {
            MessageBox::Show(L"������ ��� ���������� �����", L"������");
        }
    }

    void Cryptoprovaider::DecryptFile(Object^ sender, EventArgs^ e)
    {
        // ��������, ������ �� ���� � �����
            if (this->textBoxFilePath->Text == "") {
                MessageBox::Show(L"������� ���� ��� ����������", L"������");
                return;
            }
        std::string TofilePath;
        FolderBrowserDialog^ folderBrowserDialog = gcnew FolderBrowserDialog();
        folderBrowserDialog->Description = L"�������� ����� ��� ����������";
        if (folderBrowserDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
        {
            TofilePath = marshal_to_std_string(folderBrowserDialog->SelectedPath);
        }
        else {
            MessageBox::Show(L"������� ����� ��� ����������", L"������");
            return;
        }

        // ����� ���� ��� ����� ������
        std::string password;
        password = EnterPassword(password);
        //std::cerr << password << std::endl;
        // ��������, ������ �� ������
        if (password.empty()) {
            MessageBox::Show(L"������� ������ ��� ����������", L"������");
            return;
        }



        // �������������� ���� � ����� � std::string
        std::string filePath = marshal_to_std_string(this->textBoxFilePath->Text);
        BIGNUM* N = BN_new();
        BN_dec2bn(&N, marshal_to_std_string(this->textBoxN->Text).c_str());
        BIGNUM* en = BN_new();
        BN_dec2bn(&en, marshal_to_std_string(this->textBoxE->Text).c_str());

        // �������� ������ � Encrypt.cpp
        // �����������, ��� � ��� ���� ������� EncryptFile � Encrypt.cpp, ������� ��������� ���� � ����� � ������
        if (Decrypt(filePath, password, N, en, TofilePath)) {
            MessageBox::Show(L"���� ������� ����������", L"�����");
        }
        else {
            MessageBox::Show(L"������ ��� ����������� �����", L"������");
        }
        
    }
    

    bool Cryptoprovaider::CheckEncryptedKeyFile(std::string password) {
        std::ifstream file("encrypted_key.bin");
        if (!file.is_open()) {
            // ���� �� ������, ����������� ������
            

            // ���������� ������ ��� ������������� ��� ��� ����������� �����
            // (����� ������ ���� ��� ��� ���������� ������ ��� ����������� �����)

            return false; // ���� �� ������, �� ������ ������
        }
        file.close();
        return true; // ���� ������
    }
    std::string Cryptoprovaider::EnterPassword(std::string password) {
        System::Windows::Forms::Form^ passwordForm = gcnew System::Windows::Forms::Form();
        passwordForm->Text = L"������� ������";
        passwordForm->Size = System::Drawing::Size(300, 150);

        System::Windows::Forms::Label^ label = gcnew System::Windows::Forms::Label();
        label->Text = L"������� ������:";
        label->Location = Point(10, 20);
        label->Size = System::Drawing::Size(280, 20);
        passwordForm->Controls->Add(label);

        System::Windows::Forms::TextBox^ textBox = gcnew System::Windows::Forms::TextBox();
        textBox->Location = Point(10, 50);
        textBox->Size = System::Drawing::Size(260, 20);
        textBox->PasswordChar = '*';
        passwordForm->Controls->Add(textBox);

        System::Windows::Forms::Button^ button = gcnew System::Windows::Forms::Button();
        button->Text = L"��";
        button->Location = Point(100, 80);
        button->Size = System::Drawing::Size(100, 30);
        button->Click += gcnew EventHandler(this, &Cryptoprovaider::OnPasswordEntered);
        passwordForm->Controls->Add(button);

        passwordForm->ShowDialog();

        
        return password = marshal_to_std_string(textBox->Text);
        //std::cerr << password << std::endl;
    }
    std::string Cryptoprovaider::GenPassword(std::string password) {
        System::Windows::Forms::Form^ passwordForm = gcnew System::Windows::Forms::Form();
        passwordForm->Text = L"������� ������";
        passwordForm->Size = System::Drawing::Size(300, 150);

        System::Windows::Forms::Label^ label = gcnew System::Windows::Forms::Label();
        label->Text = L"������� ������:";
        label->Location = Point(10, 20);
        label->Size = System::Drawing::Size(280, 20);
        passwordForm->Controls->Add(label);

        System::Windows::Forms::TextBox^ textBox = gcnew System::Windows::Forms::TextBox();
        textBox->Location = Point(10, 50);
        textBox->Size = System::Drawing::Size(260, 20);
        textBox->PasswordChar = '*';
        passwordForm->Controls->Add(textBox);

        System::Windows::Forms::Button^ button = gcnew System::Windows::Forms::Button();
        button->Text = L"��";
        button->Location = Point(100, 80);
        button->Size = System::Drawing::Size(100, 30);
        button->Click += gcnew EventHandler(this, &Cryptoprovaider::OnPasswordEntered);
        passwordForm->Controls->Add(button);

        passwordForm->ShowDialog();

        // �������� ������ �� ���������
        password = marshal_to_std_string(textBox->Text);
        std::string message;
        if (!CheckPasswordComplexity(password, message)) {
            MessageBox::Show(gcnew System::String(message.c_str()), L"������ �� ������������� ����������� ���������");
            GenPassword(password); // ��������� ������ ������
        }
        return password;
    }


    void Cryptoprovaider::OnPasswordEntered(Object^ sender, EventArgs^ e) {
        System::Windows::Forms::Button^ button = dynamic_cast<System::Windows::Forms::Button^>(sender);
        System::Windows::Forms::Form^ passwordForm = dynamic_cast<System::Windows::Forms::Form^>(button->Parent);
        passwordForm->Close();
    }

    bool Cryptoprovaider::CheckPasswordComplexity(const std::string& password, std::string& message) {
        // �������� ��������� ������
        if (password.length() < 8) {
            message = "����������� ����� ������ ������ ���� 8 ��������.";
            return false;
        }
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if (isupper(c)) hasUpper = true;
            else if (islower(c)) hasLower = true;
            else if (isdigit(c)) hasDigit = true;
            else if (ispunct(c)) hasSpecial = true;
        }

        if (!hasUpper) message += "������ ������ ��������� ���� �� ���� ��������� �����.\n";
        if (!hasLower) message += "������ ������ ��������� ���� �� ���� �������� �����.\n";
        if (!hasDigit) message += "������ ������ ��������� ���� �� ���� �����.\n";
        if (!hasSpecial) message += "������ ������ ��������� ���� �� ���� ����������� ������.\n";

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
}