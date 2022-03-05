from django.db import models
from django.contrib.auth.models import User, AbstractUser
# Create your models here.
class User(AbstractUser):
    # 手机号
    # unique 为唯一性字段
    mobile = models.CharField(max_length=20, unique=True,blank=True)

    # 头像
    # upload_to为保存到响应的子目录中
    avatar = models.ImageField(upload_to='avatar/%Y%m%d/', blank=True)

    # 个人简介
    user_desc = models.TextField(max_length=500, blank=True)

    # 内部类 class Meta 用于给 model 定义元数据
    class Meta:
        db_table = 'tb_users'              # 修改的表名
        verbose_name = '用户信息'         # Admin后台显示
        verbose_name_plural = verbose_name  # Admin后台显示

    def __str__(self):
        return self.mobile
