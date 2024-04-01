// File: public/logout.js

// 获取退出按钮并添加点击事件监听器
document.addEventListener('DOMContentLoaded', (event) => {
  const logoutButton = document.getElementById('logoutButton');
  if(logoutButton) {
    logoutButton.addEventListener('click', function() {
      // 使用fetch发送注销请求
      fetch('/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      .then(function(response) {
        // 注销成功，重定向到登录页面
        window.location.href = '/login.html';
      })
      .catch(function(error) {
        console.error('Error:', error);
      });
    });
  }
});
