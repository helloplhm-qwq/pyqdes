#include "qdes.cpp"
#include <pybind11/pybind11.h>
#include <vector>

unsigned char KEY1[] = "!@#)(NHLiuy*$%^&";
unsigned char KEY2[] = "123ZXC!@#)(*$%^&";
unsigned char KEY3[] = "!@#)(*$%^&abcDEF";

int func_des(unsigned char *buff, unsigned char *key, int len)
{
  BYTE schedule[16][6];
  des_key_setup(key, schedule, DES_ENCRYPT);
  for (int i = 0; i < len; i += 8)
    des_crypt(buff + i, buff + i, schedule);
  return 0;
}

int func_ddes(unsigned char *buff, unsigned char *key, int len)
{
  BYTE schedule[16][6];
  des_key_setup(key, schedule, DES_DECRYPT);
  for (int i = 0; i < len; i += 8)
    des_crypt(buff + i, buff + i, schedule);
  return 0;
}

void LyricDecode_(unsigned char *content, int len)
{
  func_ddes(content, KEY1, len);
  func_des(content, KEY2, len);
  func_ddes(content, KEY3, len);
}

void LyricEncode_(unsigned char *content, int len)
{
  // 与LyricDecode_相反的顺序和操作
  func_des(content, KEY3, len);
  func_ddes(content, KEY2, len);
  func_des(content, KEY1, len);
}

namespace py = pybind11;

py::bytes LyricDecode(py::bytes input)
{
    // 获取输入字节数组的指针和长度
    const char *input_ptr = PyBytes_AsString(input.ptr());
    Py_ssize_t input_len = PyBytes_Size(input.ptr());

    // 复制输入数据以便修改
    std::vector<unsigned char> data(input_ptr, input_ptr + input_len);

    // 调用 LyricDecode 函数进行解密
    LyricDecode_(data.data(), data.size());

    // 创建输出字节数组
    py::bytes output(reinterpret_cast<const char *>(data.data()), data.size());

    return output;
}

py::bytes LyricEncode(py::bytes input)
{
    // 获取输入字节数组的指针和长度
    const char *input_ptr = PyBytes_AsString(input.ptr());
    Py_ssize_t input_len = PyBytes_Size(input.ptr());

    // 复制输入数据以便修改
    std::vector<unsigned char> data(input_ptr, input_ptr + input_len);

    // 调用 LyricEncode 函数进行加密
    LyricEncode_(data.data(), data.size());

    // 创建输出字节数组
    py::bytes output(reinterpret_cast<const char *>(data.data()), data.size());

    return output;
}

py::bytes DesEncrypt(py::bytes input, py::bytes key)
{
    const char *input_ptr = PyBytes_AsString(input.ptr());
    Py_ssize_t input_len = PyBytes_Size(input.ptr());
    const char *key_ptr = PyBytes_AsString(key.ptr());
    Py_ssize_t key_len = PyBytes_Size(key.ptr());

    if (key_len < 8) {
        throw std::runtime_error("Key length must be at least 8 bytes");
    }

    // 复制输入数据
    std::vector<unsigned char> data(input_ptr, input_ptr + input_len);
    std::vector<unsigned char> key_data(key_ptr, key_ptr + key_len);

    // 调用 DES 加密
    func_des(data.data(), key_data.data(), data.size());

    return py::bytes(reinterpret_cast<const char *>(data.data()), data.size());
}

py::bytes DesDecrypt(py::bytes input, py::bytes key)
{
    const char *input_ptr = PyBytes_AsString(input.ptr());
    Py_ssize_t input_len = PyBytes_Size(input.ptr());
    const char *key_ptr = PyBytes_AsString(key.ptr());
    Py_ssize_t key_len = PyBytes_Size(key.ptr());

    if (key_len < 8) {
        throw std::runtime_error("Key length must be at least 8 bytes");
    }

    // 复制输入数据
    std::vector<unsigned char> data(input_ptr, input_ptr + input_len);
    std::vector<unsigned char> key_data(key_ptr, key_ptr + key_len);

    // 调用 DES 解密
    func_ddes(data.data(), key_data.data(), data.size());

    return py::bytes(reinterpret_cast<const char *>(data.data()), data.size());
}

PYBIND11_MODULE(qdes, m) {
    m.def("LyricDecode", &LyricDecode, "Decrypt a string using the triple DES key sequence");
    m.def("LyricEncode", &LyricEncode, "Encrypt a string using the triple DES key sequence");
    m.def("DesDecrypt", &DesEncrypt, "DES encrypt with custom key", 
          py::arg("input"), py::arg("key"));
    m.def("DesDecrypt", &DesDecrypt, "DES decrypt with custom key", 
          py::arg("input"), py::arg("key"));
}
