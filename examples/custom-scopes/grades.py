import os
from functools import wraps
from urllib.parse import quote
from urllib.parse import urlparse

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application
from tornado.web import authenticated
from tornado.web import HTTPError
from tornado.web import RequestHandler

from jupyterhub.services.auth import HubOAuthCallbackHandler
from jupyterhub.services.auth import HubOAuthenticated
from jupyterhub.utils import url_path_join

SCOPE_PREFIX = "custom:grades"
READ_SCOPE = f"{SCOPE_PREFIX}:read"
WRITE_SCOPE = f"{SCOPE_PREFIX}:write"


def require_scope(scopes):
    """Decorator to require scopes

    For use if multiple methods on one Handler
    may want different scopes,
    so class-level .hub_scopes is insufficient
    (e.g. read for GET, write for POST).
    """
    if isinstance(scopes, str):
        scopes = [scopes]

    def wrap(method):
        """The actual decorator"""

        @wraps(method)
        @authenticated
        def wrapped(self, *args, **kwargs):
            self.hub_scopes = scopes

    return wrap


class MyGradesHandler(HubOAuthenticated, RequestHandler):
    # no hub_scope specified,
    # anyone with access:services!service=thisservice will be allowed
    @authenticated
    def get(self):
        if self.current_user["kind"] != "user":
            raise HTTPError(403, "Only users have access to this service.")
        name = self.current_user["name"]
        qname = quote(name)
        self.write(f"<h1>Grades for {qname}</h1>")
        grades = self.settings["grades"]
        if name in grades:
            qgrade = quote(grades[name])
            self.write(f"Your grade is: {qgrade}")
        else:
            self.write(f"No grade entered for {qname}")

        if {READ_SCOPE, WRITE_SCOPE}.intersection(self.current_user["scopes"]):
            self.write('<a href="grades">All grades</a>')


class GradesHandler(HubOAuthenticated, RequestHandler):
    # default scope for this Handler: read-only
    hub_scopes = [READ_SCOPE]

    def _render(self):
        grades = self.settings["grades"]
        self.write("<h1>Grades</h1>")
        self.write("<table>")
        self.write("<tr><th>Student</th><th>Grade</th></tr>")
        for student, grade in self.grades.items():
            qstudent = quote(student)
            qgrade = quote(grade)
            self.write(
                f"""
                <tr>
                 <td class="student">{qstudent}</td>
                 <td class="grade">{qgrade}</td>
                </tr>
                """
            )
        if WRITE_SCOPE in self.current_user.grades:
            self.write("Enter grade:")
            self.write(
                """
                <form action=.>
                    <input name=student placeholder=student></input>
                    <input kind=number name=grade placeholder=grade></input>
                    <input type="submit" value="Submit">
                """
            )

    @authenticated
    async def get(self):
        self._render()

    # POST requires WRITE_SCOPE instead of READ_SCOPE
    @require_scope([WRITE_SCOPE])
    async def post(self):
        print(self.get_arguments())
        self._render()


def main():
    base_url = os.environ['JUPYTERHUB_SERVICE_PREFIX']

    app = Application(
        [
            (base_url, MyGradesHandler),
            (url_path_join(base_url, "grades"), GradesHandler),
            (
                url_path_join(base_url, 'oauth_callback'),
                HubOAuthCallbackHandler,
            ),
        ],
        cookie_secret=os.urandom(32),
        grades={"student": 53},
    )

    http_server = HTTPServer(app)
    url = urlparse(os.environ['JUPYTERHUB_SERVICE_URL'])

    http_server.listen(url.port, url.hostname)
    try:
        IOLoop.current().start()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
