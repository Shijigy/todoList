package repository

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"user/internal/service"
)

type User struct {
	UserID         int64  `gorm:"primarykey"`
	UserName       string `gorm:"unique"`
	NickName       string
	PasswordDigest string
}

const (
	PasswordCost = 12 // 密码加密难度
)

// CheckUserExist 检查用户是否存在
func (user *User) CheckUserExist(req *service.UserRequest) bool {
	if err := DB.Where("user_name=?", req.UserName).First(&user).Error; err == gorm.ErrRecordNotFound {
		return false
	}
	return true
}

// ShowUserInfo 获取用户信息
func (user *User) ShowUserInfo(req *service.UserRequest) error {
	if exist := user.CheckUserExist(req); exist {
		return nil
	}
	return errors.New("UserName not exist")
}

// UserCreate 创建用户
func (*User) UserCreate(req *service.UserRequest) error {
	var count int64
	DB.Where("user_name=?", req.UserName).Count(&count)
	if count != 0 {
		return errors.New("UserName exist")
	}
	user := User{
		UserName: req.UserName,
		NickName: req.NickName,
	}
	// 密码加密
	_ = user.SetPassword(req.Password)
	err := DB.Create(&user).Error
	return err

}

// SetPassword 加密密码
func (user *User) SetPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
	if err != nil {
		return err
	}
	user.PasswordDigest = string(bytes)
	return nil
}

// CheckPassword 检验密码
func (user *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordDigest), []byte(password))
	return err == nil
}

// BuildUser 序列化User
func BuildUser(item User) *service.UserModel {
	userModel := &service.UserModel{
		UserID:   uint32(item.UserID),
		UserName: item.UserName,
		NickName: item.NickName,
	}
	return userModel
}
