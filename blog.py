import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Make a value secure by adding a hashed versione of the value after the |
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Splits the secure value on | and makes sure the secured value equals value
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Main handler with some convenience functions
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Adds a cookie to the browser utilizing make_secure_val
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

# Reads the cookie and make sure it the hash still translates to name
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

# Make use of set_secure_cookie to set cookie for user
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

# Sets cookie to have no content
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# Function for organizing post contenbts uniformly 
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# Resudiual function from the / path
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# Makes salt to make hash harder to crack
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Hashes the password making use of the salt created above
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Checks if password is valid 
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# Database for storing users
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

# Lookup user by id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

# Lookup user by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

# Take in all params to register user and return the isntance
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

# Logs in user with a valid password
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def like_key(name = 'default'):
    return db.Key.from_path('upvotes', name)

''' Database for storing likes. Matching them with username and post id to make sure everyone can only like a post once, used in the Like function below'''
class Likes(db.Model):
    user = db.StringProperty()
    postid = db.StringProperty()

def comm_key(name = 'default'):
    return db.Key.from_path('comms', name)

class Comments(db.Model):
    postid = db.StringProperty()
    uid = db.StringProperty()
    content = db.StringProperty(required= True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Database to store all the posts created by users
class Post(db.Model):
    uid = db.StringProperty()
    likes = db.IntegerProperty()
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

# Render front.html with all the posts.

class BlogFront(BlogHandler):
    def get(self):
        coms = Comments.all().order('-created')
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts, coms=coms)

# Renders the post page (permalink) which will have the new post
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        coms = Comments.all().order('-created')
        self.render("permalink.html", post = post, coms = coms)


''' Renders newpost.html where the user will fill out content and subject of their new posts. The post function will grab these and create a new entry in Posts database. If there's errors it will let the user know'''

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, uid = self.user.name, likes = 0)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

# These will put restrictions on user name email and password 
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

''' Renders signup-form.html and on the post it will get input that the customer entered and make sure all is there. Then it will create a new entry in the User database'''

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        return self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/blog')

''' Los in the user rendering the login-form.htmle and on post getting the username and password from what the user typed in and matching it against the database'''

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

# Calls the logout which is found above to log out user
class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/blog')

class NewCom(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            subject = post.subject
            content = post.content
            uid = post.uid
            self.render('newcom.html', subject=subject, content=content, uid=uid)
        else:
            return self.redirect('/login')

    def post(self, post_id):
        if self.user:
            comcontent = self.request.get('comcontent')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            subject = post.subject
            content = post.content
            uid = post.uid
            if comcontent:
                c = Comments(parent = comm_key(), content = comcontent, uid = self.user.name, postid = post_id)
                c.put()
                return self.redirect('/blog')
            else:
                error = "content, please!"
                self.render("newcom.html", content=content, subject=subject, uid=uid, error=error)
        else:
            return self.redirect('/login')


'''Checks to make sure the right user is trying to edit a post, once that checks out it will render edit.html and let you edit the post it will update the database'''

class Edit(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if self.user.name != post.uid:
                return self.redirect('/login')
            else:
                subject = post.subject
                content = post.content
                self.render('edit.html', subject=subject, content=content)
        else:
            return self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user.name != post.uid:
            return self.redirect('/login')

        else:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                return self.redirect('/blog')
            else:
                error = "subject and content, please!"
                self.render("edit.html", subject=subject, content=content, error=error)

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            return self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            return self.redirect('/unit2/signup')

''' Like will check if you are user. if you are the user that created the post it will redirect back to blog and not let you vote. otherwise it will let you vote storing an entry in Likes which is also checked against if you have voted alredy on this post'''
class Like(BlogHandler):
    def get(self, post_id):
        if self.user:

            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.uid != self.user.name:
                p = Likes.all().filter('user =', self.user.name).filter('postid =', post_id).get()
                if not p:
                    l = Likes(parent = like_key(), user = self.user.name, postid = post_id)
                    l.put()

                    post.likes = post.likes + 1
                    post.put()
                    return self.redirect('/blog')
                else: 
                    return self.redirect('/blog')
            else: 
                return self.redirect('/blog')
        else:
            return self.redirect('/login')

''' Checks if your are the original person who created the post and if you are it will delete the post for you. If you are not, it will redirect back to blog'''
class Delete(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if self.user.name != post.uid:
                return self.redirect('/login')
                
            else:
                db.delete(key)
                return self.redirect('/blog')
        else:
            return self.redirect('/login')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit3/rot13', Rot13),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/newcom/([0-9]+)', NewCom),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', Edit),
                               ('/signup', Register),
                               ('/delete/([0-9]+)', Delete),
                               ('/login', Login),
                               ('/like/([0-9]+)', Like),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
