#include "Cryptoprovaider.h"  // ���������� ������������ ���� � ������� Cryptoprovaider

using namespace System;
using namespace System::Windows::Forms;

// �������, �����������, ��� ����� ���������� ������ �������� � ������������ ����������� (STA)
[STAThread]
int main(array<String^>^ args)
{
    // �������� ��������� ���������� ������ ��� ����������
    Application::EnableVisualStyles();

    // ������������� ������������� � ����������� ������ �� ���������
    Application::SetCompatibleTextRenderingDefault(false);

    // ������� ��������� ����� Cryptoprovaider
    CryptN::Cryptoprovaider^ form = gcnew CryptN::Cryptoprovaider();

    // ��������� �������� ���� ���������� � ��������� ������
    Application::Run(form);

    // ���������� 0, ����� �������, ��� ��������� ����������� �������
    return 0;
}