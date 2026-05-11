#include "translator.h"
#include <QSettings>

Translator &Translator::instance()
{
    static Translator inst;
    return inst;
}

Translator::Translator(QObject *parent)
    : QObject(parent)
{
    // Load saved preference
    QSettings settings;
    QString lang = settings.value("language", "chinese").toString();
    m_lang = (lang == "english") ? Language::English : Language::Chinese;
    loadTranslations();
}

void Translator::setLanguage(Language lang)
{
    if (m_lang == lang) return;
    m_lang = lang;
    loadTranslations();

    QSettings settings;
    settings.setValue("language", lang == Language::English ? "english" : "chinese");

    emit languageChanged();
}

QString Translator::translate(const char *key) const
{
    QString k(key);
    return m_translations.value(k, k);
}

void Translator::loadTranslations()
{
    m_translations.clear();

    if (m_lang == Language::Chinese) {
        // Sidebar
        m_translations["Traffic"] = "流量";
        m_translations["Mock"] = "模拟";
        m_translations["Composer"] = "构造器";

        // Toolbar
        m_translations["Clear"] = "清除";
        m_translations["HTTPS Decrypt"] = "HTTPS 解密";
        m_translations["Export HAR"] = "导出 HAR";
        m_translations["Theme"] = "主题";
        m_translations["Light"] = "浅色";
        m_translations["Dark"] = "深色";
        m_translations["Language"] = "语言";
        m_translations["English"] = "English";
        m_translations["Chinese"] = "中文";
        m_translations["Proxy: localhost:9527"] = "代理: localhost:9527";

        // Status bar
        m_translations["Ready"] = "就绪";
        m_translations["Captured"] = "已捕获";
        m_translations["Cleared"] = "已清除";
        m_translations["Exported"] = "已导出";
        m_translations["requests to"] = "条请求到";
        m_translations["MITM: on"] = "MITM: 开启";
        m_translations["MITM: off"] = "MITM: 关闭";

        // Detail panel
        m_translations["Overview"] = "概览";
        m_translations["Request Headers"] = "请求头";
        m_translations["Request Body"] = "请求体";
        m_translations["Response Headers"] = "响应头";
        m_translations["Response Body"] = "响应体";
        m_translations["Timeline"] = "时间线";
        m_translations["URL"] = "URL";
        m_translations["Method"] = "方法";
        m_translations["Status"] = "状态";
        m_translations["Protocol"] = "协议";
        m_translations["Host"] = "主机";
        m_translations["Path"] = "路径";
        m_translations["Request Size"] = "请求大小";
        m_translations["Response Size"] = "响应大小";
        m_translations["Duration"] = "耗时";
        m_translations["Time"] = "时间";
        m_translations["Size"] = "大小";

        // Traffic list
        m_translations["#"] = "#";
        m_translations["Filter by host, path, method..."] = "按主机、路径、方法过滤...";

        // Body preview
        m_translations["Formatted"] = "格式化";
        m_translations["Raw"] = "原始";
        m_translations["Hex"] = "十六进制";
        m_translations["Preview"] = "预览";
        m_translations["JSON"] = "JSON";
        m_translations["HTML"] = "HTML";
        m_translations["Image"] = "图片";
        m_translations["Text"] = "文本";
        m_translations["(empty)"] = "(空)";
        m_translations["JSON Parse Error"] = "JSON 解析错误";

        // Timeline
        m_translations["DNS"] = "DNS";
        m_translations["Connect"] = "连接";
        m_translations["TLS"] = "TLS";
        m_translations["TTFB"] = "TTFB";
        m_translations["Download"] = "下载";
        m_translations["Total"] = "总计";

        // Certificate
        m_translations["Certificate ready"] = "证书就绪";
        m_translations["Certificate not ready"] = "证书未就绪";
        m_translations["CA cert installed"] = "CA 证书已安装";
        m_translations["CA cert not installed"] = "CA 证书未安装";

        // Composer
        m_translations["Send"] = "发送";
        m_translations["Request"] = "请求";
        m_translations["Headers"] = "请求头";
        m_translations["Body"] = "请求体";
        m_translations["Response"] = "响应";
        m_translations["Status: -"] = "状态: -";
        m_translations["Status: Sending..."] = "状态: 发送中...";
        m_translations["Status: %1 %2"] = "状态: %1 %2";
        m_translations["--- Headers ---"] = "--- 请求头 ---";
        m_translations["--- Body ---"] = "--- 响应体 ---";

        // Mock
        m_translations["+ Add Rule"] = "+ 添加规则";
        m_translations["- Remove"] = "- 删除";
        m_translations["On"] = "启用";
        m_translations["Match"] = "匹配";
        m_translations["Pattern"] = "模式";
        m_translations["Action"] = "动作";
        m_translations["Target"] = "目标";
        m_translations["New Rule"] = "新规则";
        m_translations["Exact"] = "精确";
        m_translations["Contains"] = "包含";
        m_translations["Wildcard"] = "通配符";
        m_translations["Regex"] = "正则";
        m_translations["MapLocal"] = "本地映射";
        m_translations["AutoResponder"] = "自动响应";
    }
    // English is the default - keys themselves are English, so no mapping needed
}
