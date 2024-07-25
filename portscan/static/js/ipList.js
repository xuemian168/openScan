// 获取所有具有recheckButton类的按钮元素
var recheckButtons = document.querySelectorAll(".recheckButton");

// 为每个按钮添加点击事件监听器
recheckButtons.forEach(function (button) {
    button.addEventListener("click", function () {
        var ip = this.getAttribute("data-ip");
        var port = this.getAttribute("data-port");

        var apiUrl = `/api/recheck.do?ip=${ip}&port=${port}`;
        button.disable = true;
        button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 加载中...';
        // 发起HTTP GET请求
        fetch(apiUrl)
            .then(function (response) {
                return response.json(); // 解析响应为JSON
            })
            .then(function (data) {
                // 根据响应显示提示框
                if (data.result === true) {
                    alert("开启");
                } else {
                    alert("已关闭");
                }
            })
            .catch(function (error) {
                alert("Error occurred: " + error.message);
            })
            .finally(function () {
                // 1秒后解除禁用状态
                setTimeout(function () {
                    button.disabled = false;
                    button.innerHTML = '<i class="fa-solid fa-arrow-rotate-right"></i> 复查'; // 恢复按钮文本
                }, 600); // 1000毫秒 = 1秒
            });
    });
});

// 获取所有sshButton类的按钮元素
var sshButtons = document.querySelectorAll(".sshButton");

// 为每个按钮添加点击事件监听器
sshButtons.forEach(function (button) {
    button.addEventListener("click", function () {
        var ip = this.getAttribute("data-ip");
        var port = this.getAttribute("data-port");

        var apiUrl = `/api/ssh_weak_password_check.do`;

        // 构建POST请求的数据
        var data = {
            ip: ip,
            port: port
        };
        button.disabled = true;
        button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 加载中...'; // 使用加载图标
        // 发起HTTP POST请求
        fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        })
            .then(function (response) {
                return response.json(); // 解析响应为JSON
            })
            .then(function (data) {
                // 根据响应显示提示框
                if (data.success === true) {
                    alert("发现弱口令:  " + data.password);
                } else {
                    alert(data.ip + "暂未发现弱口令");
                }
            })
            .catch(function (error) {
                alert("Error occurred: " + error.message);
            })
            .finally(function () {
                // 1秒后解除禁用状态
                setTimeout(function () {
                    button.disabled = false;
                    button.innerHTML = '<i class="fa-solid fa-key"></i> 弱口令检查'; // 恢复按钮文本
                }, 600); // 1000毫秒 = 1秒
            });
    });
});

var smbButtons = document.querySelectorAll(".smbButton");

// 为每个按钮添加点击事件监听器
smbButtons.forEach(function (button) {
    button.addEventListener("click", function () {
        var ip = this.getAttribute("data-ip");

        var apiUrl = `/api/ms17_010_check.do`;

        // 构建POST请求的数据
        var data = {
            ip: ip,
        };

        // 发起HTTP POST请求
        fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        })
            .then(function (response) {
                return response.json(); // 解析响应为JSON
            })
            .then(function (data) {
                // 根据响应显示提示框
                if (data.result === "MS17-010") {
                    alert(ip + "存在永恒之蓝");
                } else {
                    alert(ip + "暂未发现永恒之蓝");
                }
            })
            .catch(function (error) {
                alert("Error occurred: " + error.message);
            });
    });
});


document.addEventListener("DOMContentLoaded", function () {
    // 获取刷新按钮元素
    var flushButton = document.getElementById("flushButton");

    // 添加点击事件监听器
    flushButton.addEventListener("click", function () {
        // 构建 API URL
        var apiUrl = "/api/flush_online";

        // 发起 GET 请求到后台 API
        fetch(apiUrl, {
            method: "GET"
        })
            .then(function (response) {
                if (response.ok) {
                    console.log("刷新成功");
                } else {
                    console.error("刷新失败");
                }
            })
            .catch(function (error) {
                console.error("刷新失败：" + error.message);
            });
    });
});

// 获取刷新按钮元素
var flushButton = document.getElementById("flushButton");

// 点击按钮后执行的函数
function handleClick() {
    // 禁用按钮
    flushButton.disabled = true;
    flushButton.textContent = " 刷新中...";

    // 添加加载图标
    var spinner = document.createElement("span");
    spinner.className = "spinner-border spinner-border-sm";
    flushButton.prepend(spinner);

    // 模拟加载过程（假设为10秒）
    setTimeout(function () {
        // 恢复按钮状态
        flushButton.disabled = false;
        flushButton.textContent = "刷新";
        location.reload();
    }, 10000); // 10秒

    // 在这里可以添加刷新页面的逻辑
}

// 添加点击事件监听器
flushButton.addEventListener("click", handleClick);

// 获取返回顶部按钮元素
var scrollTopButton = document.getElementById("scrollTopButton");

// 滚动时显示或隐藏返回顶部按钮
window.addEventListener("scroll", function () {
    if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
        scrollTopButton.style.display = "block";
    } else {
        scrollTopButton.style.display = "none";
    }
});

// 点击按钮返回顶部
scrollTopButton.addEventListener("click", function () {
    document.body.scrollTop = 0; // Safari
    document.documentElement.scrollTop = 0; // Chrome, Firefox, IE, Edge
});
