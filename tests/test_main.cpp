#include <gtest/gtest.h>
#include <QApplication>

int main(int argc, char **argv)
{
    // Qt app needed for some tests that use Qt types
    QCoreApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
