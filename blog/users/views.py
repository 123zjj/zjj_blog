from django.contrib.auth import authenticate, login
from django.shortcuts import render
from django.contrib.auth.mixins import LoginRequiredMixin
# Create your views here.
from django.views import View
from django.http.response import JsonResponse

# from home.models import ArticleCategory, Article
from home.models import ArticleCategory, Article
from utils.response_code import RETCODE
import logging
from django.shortcuts import redirect
from django.urls import reverse
from django.http import HttpResponse
from django.contrib.auth import logout
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

logger = logging.getLogger('django')
from random import randint
from libs.yuntongxun.sms import CCP
from django.http.response import HttpResponseBadRequest
import re
from users.models import User
from django.db import DatabaseError


#  注册视图
class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        # 1接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2验证数据
        # 2.1判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必传参数')
        # 2.2判断手机号是否合法,必须以1开始3-9，九位
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')
        # 2.3判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')
        # 2.4判断两次密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次输入的密码不一致')

        # 2.5验证短信验证码和redis的是否一致
        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get('sms:%s' % mobile)
        if sms_code_server is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != sms_code_server.decode():
            return HttpResponseBadRequest('短信验证码错误')

        # 3保存用户的注册数据
        # create_user可以使用系统的方法对密码进行加密
        try:
            user = User.objects.create_user(username=mobile,
                                            mobile=mobile,
                                            password=password)
        except DatabaseError:
            return HttpResponseBadRequest('注册失败')

        from django.contrib.auth import login
        login(request, user)

        # 返回响应注册跳转到指定页面，后期再指定页面
        # reverse是可以通过namespace:name获取视图所对应的路由
        response = redirect(reverse('home:index'))
        # return HttpResponse('注册成功，重定向到首页')
        # 设置cookie信息，以方便首页中用户信息的展示判断和用户信息的展示
        # 登录状态，会话结束后自动过期
        response.set_cookie('is_login', True)
        # 设置用户名有效期一年
        response.set_cookie('username', user.username, max_age=365 * 24 * 3600)

        return response


class ImageCodeView(View):

    def get(self, request):
        # 1获取前端传递过来的参数uuid
        uuid = request.GET.get('uuid')
        # 2判断参数uuid是否为None
        if uuid is None:
            return HttpResponseBadRequest('请求参数错误')
        # 3获取验证码内容和验证码图片内容,通过调用captcha来生成图片验证码
        text, image = captcha.generate_captcha()
        # 将图片验内容保存到redis中，并设置过期时间，uuid作为key，图片内容作为value
        redis_conn = get_redis_connection('default')
        redis_conn.setex('img:%s' % uuid, 300, text)
        # 返回响应，将生成的图片以content_type为image/jpeg的形式返回给请求
        return HttpResponse(image, content_type='image/jpeg')


class SmsCodeView(View):

    def get(self, request):
        # 1接受参数   以查询字符串的形式传递
        mobile = request.GET.get('mobile')
        image_cold = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        # 2参数验证

        #      2.1验证参数是否齐全
        if not all([mobile, image_cold, uuid]):
            return JsonResponse({'cold': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要的参数信息'})
        #      2.2进行图片验证码的验证
        #      2.3首先链接redis获取redis中的图片验证码
        redis_conn = get_redis_connection('default')
        redis_image_cold = redis_conn.get('img:%s' % uuid)
        #      2.4此时图片有一定时效，判断是否存在或者过期
        if redis_image_cold is None:
            return JsonResponse({'cold': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码已过期'})
        #      2.5如果未过期，获取之后删除图片验证码
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
        #      2.6比对图片验证码,注意大小写，redis的数据是bytes类型
        if redis_image_cold.decode().lower() != image_cold.lower():
            return JsonResponse({'cold': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码错误'})
        # 3生成随机的6位短信验证码
        sms_cold = '%06d' % randint(0, 999999)
        # 为了后期比对方便可以记录到日志中
        logger.info(sms_cold)
        # 4保存短信验证码到redis中
        redis_conn.setex('sms:%s' % mobile, 300, sms_cold)
        # 5发送短信
        # 注意： 测试的短信模板编号为1
        # 参数1 测试的手机号
        # 参数2 列表：您的验证码为{1}，请于{2}内正确输入，如非本人操。。
        #  {1}是短信验证码 {2} 短信有效期
        # 参数3  只能选模板1
        CCP().send_template_sms(mobile, [sms_cold, 5], 1)
        # 6返回响应（前端进行倒计时）
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功'})


class LoginView(View):

    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        # 1接受参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')

        # 2校验参数
        # # 2.1判断参数是否齐全
        # if not all([mobile, password]):
        #     return HttpResponseBadRequest('缺少必传参数')

        # 2.2判断手机号是否正确符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号')

        # 2.3判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码最少8位，最长20位')

        # 3认证登录用户
        # 4认证字段已经在User模型中的USERNAME_FIELD = 'mobile'修改
        user = authenticate(mobile=mobile, password=password)

        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')

        # 实现状态保持
        login(request, user)

        # 响应登录结果，跳转到首页
        # 根据next参数来进行页面的跳转
        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))

        # 设置状态保持的周期
        if remember != 'on':
            # 没有记住用户：浏览器关闭之后就过期
            request.session.set_expiry(0)
            # 设置cookie
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        else:
            # 记住用户：None表示两周后过期,默认两周
            request.session.set_expiry(None)
            # 设置cookie
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        # 返回响应
        return response


class LogoutView(View):

    def get(self, request):
        # 1清除session
        logout(request)

        # 退出登录，重定向到登录页
        response = redirect(reverse('home:index'))

        # 退出登录时清除cookie中的登录状态
        response.delete_cookie('is_login')
        # response.delete_cookie('username')

        return response


from django.views import View


class ForgetPasswordView(View):

    def get(self, request):

        return render(request, 'forget_password.html')

    def post(self, request):
        # 1接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2验证数据
        # 2.1判断参数是否齐全，验证数据
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必传参数')

        # 2.2判断手机号是否存在
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')

        #  2.3判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        # 2.4判断两次密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次输入的密码不一致')

        # 2.5验证短信验证码
        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get('sms:%s' % mobile)
        if sms_code_server is None:  # 因为短信的验证码有时效的
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != sms_code_server.decode():
            return HttpResponseBadRequest('短信验证码错误')

        # 3根据手机号查询数据
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 3.1如果该手机号不存在，则注册个新用户
            try:
                User.objects.create_user(username=mobile, mobile=mobile, password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 3.2如果手机号存在则修改用户密码
            user.set_password(password)
            user.save()  # 保存用户信息
            #  4跳转到登录页面
        response = redirect(reverse('users:login'))
        # 返回响应
        return response


#     LoginRequiredMixin判断用户是否登录，系统自带的
class UserCenterView(LoginRequiredMixin, View):
    def get(self, request):
        # 获取用户信息
        user = request.user

        # 组织模板渲染数据
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        # 接收数据
        user = request.user  # 获取之前的user信息哦
        avatar = request.FILES.get('avatar')  # 头像信息传递过来的是一个file文件
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)

        # 更新cookie中的username信息
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                # 头像信息的保存需要指定路径如果不指定路径就默认保存在工程下
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面，重定向操作
        response = redirect(reverse('users:center'))
        # 更新cookie信息
        response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        return response


class WriteBlogView(LoginRequiredMixin, View):

    def get(self, request):
        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        context = {
            'categories': categories
        }

        return render(request, 'write_blog.html', context=context)

    def post(self, request):
        # 接收数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user

        # 验证数据是否齐全
        if not all([avatar, title, category_id, sumary, content]):
            return HttpResponseBadRequest('参数不全')

        # 判断文章分类id数据是否正确
        try:
            article_category = ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类信息')

        # 保存到数据库
        try:
            article = Article.objects.create(
                author=user,
                avatar=avatar,
                category=article_category,
                tags=tags,
                title=title,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，请稍后再试')

        # 返回响应，跳转到文章详情页面
        # 暂时先跳转到首页
        return redirect(reverse('home:index'))
