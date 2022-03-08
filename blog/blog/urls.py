"""blog URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import django
from django.conf.global_settings import MEDIA_ROOT
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.contrib.staticfiles.views import serve
from django.template.defaulttags import url
from django.urls import path, include, re_path
from django.conf import settings
#  1.导入系统的logging
import logging

#  2.创建获取日志器
# logger=logging.getLogger('django')
#
# from django.http import HttpResponse
# def log(request):
#  #   3.使用日记信息记录
#     logger.info('info')
#     return HttpResponse('test')
from patterns import patterns

urlpatterns = (
    path('admin/', admin.site.urls),
    # include 的参数中首先设置一个元祖，urlconf_module, app_name
    # urlconf_module    子应用路由
    # app_name  子应用名字

    # namespace命名空间，可以很好滴防止不同子应用的路由名字而导致的冲突
    path('', include(('users.urls', 'users'), namespace='users')),  # 设置元组参数
    # path('', log)
    path('', include(('home.urls', 'home'), namespace='home')),
    re_path(
     r"^media/(?P<path>.+)$", django.views.static.serve, {'document_root': settings.MEDIA_ROOT}
        ),
)
# # 图片访问的路由
# # 以下代码为设置图片访问路由规则

# from django.conf.urls.static import static
#
# # urlpatterns +=staticfiles_urlpatterns()
# urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)