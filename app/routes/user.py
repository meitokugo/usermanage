# coding:utf-8
from ..base import base
from ..models import User, Organization, Role, OnLine
from flask import render_template, request
from flask import g, jsonify
import hashlib
from flask_login import login_user, logout_user, login_required, \
    current_user
from datetime import datetime
from .. import  db
import uuid
from sqlalchemy import asc
from sqlalchemy import desc
import flask_excel as excel

@base.route('/login', methods=['GET'])
def login():
    return render_template('login/index.html')

@base.route('/securityJsp/base/SyuserForm.jsp', methods=['GET'])
def form_user():
    return render_template('user/form.html', id=request.args.get('id', ''))

@base.route('/securityJsp/base/SyuserOrganizationGrant.jsp', methods=['GET'])
def grant_user_organization_page():
    return render_template('user/grant_organization.html', id=request.args.get('id', ''))

@base.route('/securityJsp/base/SyuserRoleGrant.jsp', methods=['GET'])
def grant_user_role_page():
    return render_template('user/grant_role.html', id=request.args.get('id', ''))

@base.route('/base/syuser!grantOrganization.action', methods=['POST'])
def grant_user_organization():
    id = request.form.get('id')
    ids = request.form.get('ids')

    user = User.query.get(id)

    if not ids:
        user.organizations = []
    else:
        idList = ids.split(',')
        user.organizations = [Organization.query.get(rid) for rid in idList]

    db.session.add(user)

    return jsonify({'success': True})

@base.route('/base/syuser!grantRole.action', methods=['POST'])
def grant_user_role():
    id = request.form.get('id')
    ids = request.form.get('ids')

    user = User.query.get(id)

    if not ids:
        user.roles = []
    else:
        idList = ids.split(',')
        user.roles = [Role.query.get(rid) for rid in idList]

    db.session.add(user)

    return jsonify({'success': True})

def record_login_history(type):
    online = OnLine()
    online.ID = str(uuid.uuid4())
    online.LOGINNAME = current_user.LOGINNAME
    online.IP = request.remote_addr
    online.TYPE = type
    db.session.add(online)

@base.route('/base/syuser!doNotNeedSessionAndSecurity_logout.action', methods=['POST'])
def do_logout():
    record_login_history(0)
    logout_user()
    return jsonify({'success': True})

@base.route('/base/syuser!doNotNeedSessionAndSecurity_login.action', methods=['POST'])
def do_login():
    #检查用户名是否存在
    user = User.query.filter_by(LOGINNAME=request.form['username']).first()
    
    if user is not None:
        md = hashlib.md5()
        #提交的密码MD5加密
        md.update(request.form['password'].encode('utf-8'))
        #MD5加密后的内容同数据库密码比较
        if md.hexdigest() == user.PWD:
            login_user(user)
            record_login_history(1)
            return jsonify({'name': '登录成功~', 'status': '1', 'url': '/'})
    return jsonify({'name': '登录失败,账号密码错误~', 'status': '0'})

@base.route('/securityJsp/base/Syuser.jsp', methods=['GET'])
def index_user():
    return render_template('user/index.html')

@base.route('/base/syuser!grid.action', methods=['POST'])
def user_grid():
    filters = []
    if request.form.get('loginname'):
        filters.append(User.LOGINNAME.like('%' + request.form.get('loginname') + '%'))
    if request.form.get('name'):
        filters.append(User.NAME.like('%' + request.form.get('name') + '%'))
    if request.form.get('sex'):
        filters.append(User.SEX == request.form.get('sex'))
    if request.form.get('createdatetime1') and request.form.get('createdatetime2'):
        filters.append(User.CREATEDATETIME >  request.form.get('createdatetime1'))
        filters.append(User.CREATEDATETIME <  request.form.get('createdatetime2'))

    order_by = []
    if request.form.get('sort'):
        if request.form.get('order') == 'asc':
            order_by.append(asc(getattr(User,request.form.get('sort').upper())))
        elif request.form.get('order') == 'desc':
            order_by.append(desc(getattr(User,request.form.get('sort').upper())))
        else:
            order_by.append(getattr(User,request.form.get('sort').upper()))

    page = request.form.get('page', 1, type=int)
    rows = request.form.get('rows', 10, type=int)
    pagination = User.query.filter(*filters).order_by(*order_by).paginate(
        page, per_page=rows, error_out=False)
    users = pagination.items

    return jsonify({'rows': [user.to_json() for user in users], 'total': pagination.total})

@base.route('/base/syuser!getById.action', methods=['POST'])
def syuser_getById():
    user = User.query.get(request.form.get('id'))

    if user:
        return jsonify(user.to_json())
    else:
        return jsonify({'success': False, 'msg': 'error'})

@base.route('/base/syuser!update.action', methods=['POST'])
def syuser_update():
    id = request.form.get('data.id')
    loginname = request.form.get('data.loginname')
    
    if User.query.filter(User.LOGINNAME == loginname).filter(User.ID != id).first():
        return jsonify({'success': False, 'msg': '更新用户失败，用户名已存在！'})

    user = User.query.get(id)

    user.UPDATEDATETIME = datetime.now()
    user.LOGINNAME = request.form.get('data.loginname')
    user.NAME = request.form.get('data.name')
    user.SEX = request.form.get('data.sex')
    user.PHOTO = request.form.get('data.photo')

    db.session.add(user)

    return jsonify({'success': True, 'msg': '更新成功！'})

@base.route('/base/syuser!save.action', methods=['POST'])
def syuser_save():
    if User.query.filter_by(LOGINNAME = request.form.get('data.loginname')).first():
        return jsonify({'success': False, 'msg': '新建用户失败，用户名已存在！'})

    user = User()

    user.ID = str(uuid.uuid4())

    md = hashlib.md5()
    md.update('123456'.encode('utf-8'))
    user.PWD = md.hexdigest()

    user.NAME = request.form.get('data.name')
    user.LOGINNAME = request.form.get('data.loginname')
    user.SEX = request.form.get('data.sex')
    user.PHOTO = request.form.get('data.photo')

    # add current use to new user
    #current_user.roles.append(user)

    db.session.add(user)

    return jsonify({'success': True, 'msg': '新建用户成功！默认密码：123456'})

@base.route('/base/syuser!delete.action', methods=['POST'])
def syuser_delete():
    user = User.query.get(request.form.get('id'))
    if user:
        db.session.delete(user)

    return jsonify({'success': True})

@base.route('/base/syuser!doNotNeedSecurity_updateCurrentPwd.action', methods=['POST']) 
def syuser_update_pwd():
    user = User.query.get(current_user.ID)

    if user:
        md = hashlib.md5()
        md.update(request.form.get('data.pwd').encode('utf-8'))
        user.PWD = md.hexdigest()
        db.session.add(user)
    return jsonify({'success': True})

@base.route('/securityJsp/userInfo.jsp', methods=['GET'])
def syuser_info():
    resources = []
    resourceTree = []

    resources += [res for org in current_user.organizations for res in org.resources if org.resources]
    resources += [res for role in current_user.roles for res in role.resources if role.resources]
    
    # remove repeat
    new_dict = dict()
    for obj in resources:
        if obj.ID not in new_dict:
            new_dict[obj.ID] = obj

    for resource in new_dict.values():
        res = {}
        if resource.parent:
            res['pid'] = resource.parent.ID 
        res['id'] = resource.ID
        res['text'] = resource.NAME
        res['iconCls'] = resource.ICONCLS
        resourceTree.append(res)

    return render_template('user/userinfo.html', current_user = current_user, resourceTreeJson = resourceTree)


@base.route('/base/syuser!export.action', methods=['POST'])
def user_export():
    rows = []
    rows.append(['登录名', '姓名', '创建时间', '修改时间', '性别'])

    users = User.query.all()
    for user in users:
        row = []
        row.append(user.LOGINNAME)
        row.append(user.NAME)
        row.append(user.CREATEDATETIME)
        row.append(user.UPDATEDATETIME)
        if user.SEX == '0':
            row.append('女')
        elif user.SEX == '1':
            row.append('男')
        rows.append(row)

    return excel.make_response_from_array(rows, "csv",
                                          file_name="user")
