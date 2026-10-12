#include <vector>
#include <c4/base64.hpp>
#include <ryml.hpp>

static bool YamlGetByteList(ryml::ConstNodeRef seq, std::vector<uint8_t>& out)
{
    out.reserve(seq.num_children());
    for (ryml::ConstNodeRef item : seq.children())
    {
        uint32_t byte;
        if (!item.has_val() || item.val_is_null() || !ryml::from_chars(item.val(), &byte))
        {
            return false;
        }

        if (byte > 0xFF) {
            return false;
        }

        out.push_back(static_cast<uint8_t>(byte));
    }
    return true;
}

static bool YamlGetBinary(ryml::ConstNodeRef val, std::vector<uint8_t>& out)
{
    if (!val.has_val_tag() || val.val_tag() != "!!binary") {
        return false;
    }

    std::string clean;
    for (size_t i = 0; i < val.val().len; i++) {
        const char c = val.val().str[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            clean.push_back(c);
        }
    }

    if (clean.empty() || !c4::base64_valid(clean.c_str(), clean.size())) {
        return false;
    }

    size_t bytesNeeded = 0;
    if (!c4::base64_decode(clean.c_str(), clean.size(), nullptr, 0, &bytesNeeded)) {
        return false;
    }

    out.resize(bytesNeeded);
    if (!c4::base64_decode(clean.c_str(), clean.size(), out.data(), out.size(), &bytesNeeded)) {
        return false;
    }

    return true;
}

static bool YamlGetBytes(ryml::ConstNodeRef parent, ryml::csubstr key, std::vector<uint8_t>& data)
{
    const ryml::ConstNodeRef node = parent.find_child(key);
    if (node.invalid())
        return false;

    //Handle byte array
    if (node.is_seq()) {
        if (!YamlGetByteList(node, data))
            return false;
    }// base64 expect !!binary tag maybe
    else if (node.has_val() && !node.val_is_null()) {
        if (!YamlGetBinary(node, data))
            return false;
    }

    return true;
}

static bool YamlGetMap(ryml::ConstNodeRef parent, ryml::csubstr key, ryml::ConstNodeRef& map)
{
    map = parent.find_child(key);
    if (map.invalid() || !map.is_map())
        return false;

    return true;
}

static bool YamlGetStringView(ryml::ConstNodeRef parent, ryml::csubstr key, std::string_view& str)
{
    const ryml::ConstNodeRef node = parent.find_child(key);
    if (node.invalid() || !node.has_val() || node.val_is_null() || node.val().len == 0) {
        return false;
    }

    str = std::string_view(node.val().str, node.val().len);
    return true;
}

static bool YamlGetString(ryml::ConstNodeRef parent, ryml::csubstr key, std::string& str)
{
    const ryml::ConstNodeRef node = parent.find_child(key);
    if (node.invalid() || !node.has_val() || node.val_is_null() || node.val().len == 0) {
        return false;
    }

    str.assign(node.val().str, node.val().len);
    return true;
}

static bool YamlGetBool(ryml::ConstNodeRef parent, ryml::csubstr key, bool bDefault)
{
    const ryml::ConstNodeRef node = parent.find_child(key);
    if (node.invalid() || !node.has_val() || node.val_is_null()) {
        return bDefault;
    }

    const ryml::csubstr val = node.val();
    if (val == "true" || val == "True" || val == "TRUE") { return true; }
    if (val == "false" || val == "False" || val == "FALSE") { return false; };

    return bDefault;
}

template<typename T, typename = typename std::enable_if<std::is_arithmetic<T>::value, T>::type>
static bool YamlGetNumeric(ryml::ConstNodeRef node, T& val)
{
    if (node.invalid() || !node.has_val() || node.val_is_null()) {
        return false;
    }

    if (!ryml::from_chars(node.val(), &val)) {
        return false;
    }

    return true;
}

template<typename T, typename = typename std::enable_if<std::is_arithmetic<T>::value, T>::type>
static bool YamlGetNumeric(ryml::ConstNodeRef parent, ryml::csubstr key, T& val)
{
    const ryml::ConstNodeRef node = parent.find_child(key);
    return YamlGetNumeric(node, val);
}