import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--binary-ninja-path", action="store", default="/opt/binaryninja/binaryninja"
    )
    parser.addoption(
        "--rpyc", action="store_true", help="Use hugsy's binary ninja headless server"
    )


@pytest.fixture(scope="module")
def binary_ninja_path(request):
    return request.config.getoption("--binary-ninja-path")


@pytest.fixture(scope="module")
def bg_init(request):
    if request.config.getoption("--rpyc"):
        from bingoggles.vfa import BGInitRpyc as BGInitialization
    else:
        from bingoggles.vfa import BGInit as BGInitialization
    return BGInitialization
