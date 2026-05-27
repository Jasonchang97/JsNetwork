#include "app/application.h"
#include "app/version.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("JsNetwork");
    app.setApplicationVersion(JSNETWORK_VERSION);
    app.setOrganizationName("JsNetwork");

    Application jsn;
    jsn.start();

    return app.exec();
}
