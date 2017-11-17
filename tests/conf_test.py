""" Test database fixture. """
import os
import pytest

from corptest import APP
from corptest.database import BASE, ENGINE

from corptest.model_sources import DB_SESSION
from corptest.model_properties import init_db
@pytest.fixture(scope='session')
def app(request):
    # Establish an application context before running the tests.
    ctx = APP.app_context()
    ctx.push()

    def teardown():
        ctx.pop()
        os.unlink(APP.config["SQL_PATH"])

    request.addfinalizer(teardown)
    return APP


@pytest.fixture(scope='session')
def db(app, request):
    """Session-wide test database."""
    def teardown():
        BASE.metadata.drop_all(bind=ENGINE)

    BASE.metadata.app = app
    init_db()

    request.addfinalizer(teardown)
    return BASE.metadata


@pytest.fixture(scope='function')
def session(db, request):
    """Creates a new database session for a test."""
    def teardown():
        BASE.metadata.drop_all(bind=ENGINE)
        BASE.commit

    return DB_SESSION
