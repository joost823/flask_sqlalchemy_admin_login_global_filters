# flask_sqlalchemy_admin_login_global_filters
An example application of filtering all queries based on the id of some current user in flask admin.

Uses flask-login for loggin in, flask-admin for displaying administrative information without too much hassle, and SQLAlchemy for query contruction.

A user has certain books (one to many), books have pages (one to many), and pages have words (many to many). A book belongs to a user, and when the user is logged in, all the pages, words, and books will only be visible to the logged in user. The user can not access any other information, even by editing the url/curl etc (at least, that's what I hope). 

If the user is not logged in, all information is visible. This is just for illustrative purposes, but it could be easy shielded off by overwriting the `is_accessible` method of your modelview.

    class MyModelView(ModelView):
        def is_accessible(self):
            return login.current_user.is_authenticated

Adjusting the queries is kind of a hassle, but this is the only way I managed to achieve the current result, because the queries need to be filtered on information which is a coulpe of joins away.

It's based on a mixture of the following questions/examples:

https://stackoverflow.com/questions/2885415/what-is-the-best-way-pre-filter-user-access-for-sqlalchemy-queries

https://stackoverflow.com/questions/50740800/sqlalchemy-pre-filtered-query-with-optional-workaround

https://bitbucket.org/zzzeek/sqlalchemy/wiki/UsageRecipes/GlobalFilter

https://bitbucket.org/zzzeek/sqlalchemy/wiki/UsageRecipes/PreFilteredQuery

https://github.com/miguelgrinberg/sqlalchemy-soft-delete/blob/master/app.py

https://github.com/flask-admin/flask-admin/blob/master/examples/auth-flask-login/app.py
