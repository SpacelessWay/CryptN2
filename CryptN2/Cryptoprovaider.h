#pragma once
#include <openssl/bn.h>
#include <string>
namespace CryptN {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// Сводка для Cryptoprovaider
	/// </summary>
	public ref class Cryptoprovaider : public System::Windows::Forms::Form
	{
	public:
		Cryptoprovaider(void);

	protected:
		/// <summary>
		/// Освободить все используемые ресурсы.
		/// </summary>
		~Cryptoprovaider();

	private:
		/// <summary>
		/// Обязательная переменная конструктора.
		/// </summary>
		System::ComponentModel::Container^ components;

		// Компоненты формы
		Label^ labelTitle;
		Label^ labelN;
		Label^ labelE;
		TextBox^ textBoxFilePath;
		TextBox^ textBoxN;
		TextBox^ textBoxE;
		Button^ buttonSelectFile;
		Button^ buttonReplaceKey;
		Label^ labelPublicKey;

		Button^ buttonRefreshKey;
		Button^ buttonEncrypt;
		Button^ buttonDecrypt;

		// Методы для генерации и обновления ключа
		void GeneratePublicKey(void);
		void RefreshPublicKey(Object^ sender, EventArgs^ e);

		// Методы для шифрования и дешифрования
		void EncryptFile(Object^ sender, EventArgs^ e);
		void DecryptFile(Object^ sender, EventArgs^ e);
		void ReplacePublicKey(Object^ sender, EventArgs^ e);
		bool LoadPublicKeyFromFile(BIGNUM** N, BIGNUM** e);
		bool CheckEncryptedKeyFile(std::string password);
		std::string GenPassword(std::string password);
		void OnPasswordEntered(Object^ sender, EventArgs^ e);
		std::string EnterPassword(std::string password);
		bool CheckPasswordComplexity(const std::string& password, std::string& message);



		// Метод для выбора файла
		void SelectFile(Object^ sender, EventArgs^ e);


#pragma region Windows Form Designer generated code
		/// <summary>
		/// Требуемый метод для поддержки конструктора — не изменяйте 
		/// содержимое этого метода с помощью редактора кода.
		/// </summary>
		void InitializeComponent(void);
#pragma endregion
	};
}