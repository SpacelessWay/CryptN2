#include "Cryptoprovaider.h"  // Подключаем заголовочный файл с классом Cryptoprovaider

using namespace System;
using namespace System::Windows::Forms;

// Атрибут, указывающий, что поток приложения должен работать в однопоточном апартаменте (STA)
[STAThread]
int main(array<String^>^ args)
{
    // Включаем поддержку визуальных стилей для приложения
    Application::EnableVisualStyles();

    // Устанавливаем совместимость с рендерингом текста по умолчанию
    Application::SetCompatibleTextRenderingDefault(false);

    // Создаем экземпляр формы Cryptoprovaider
    CryptN::Cryptoprovaider^ form = gcnew CryptN::Cryptoprovaider();

    // Запускаем основной цикл приложения с созданной формой
    Application::Run(form);

    // Возвращаем 0, чтобы указать, что программа завершилась успешно
    return 0;
}