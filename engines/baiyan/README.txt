# ============================================================
#  Baiyan (白砚) — 网络资产测绘与信息收集工具
# ============================================================

Baiyan 是一个用 Go 编写的综合性网络资产发现工具，集成子域名收集、端口扫描、HTTP 探活、CDN/WAF 识别、目录扫描和指纹识别等功能，结果输出为 XLSX 工作簿。

## 目录结构

  baiyan/
  ├── cmd/baiyan/main.go    # 主入口
  ├── internal/baiyan/       # 核心逻辑包
  ├── lib/                    # 嵌入的外部工具
  │   ├── masscan/masscan        # 端口扫描 (masscan)
  │   ├── subfinder/subfinder    # 子域名收集 (subfinder)
  │   ├── ob/observer_ward       # 指纹识别 (observer_ward)
  │   ├── dirscan/dirscan        # 目录扫描 (dirscan)
  │   ├── ESD/                   # 字典爆破子域 (ESD)
  │   └── OneForAll/             # CDN 数据 (IP CIDR + CNAME 关键字)
  ├── config/                  # 配置文件目录 (首次运行自动生成)
  │   ├── spaceConfig.ini       # FOFA / Quake / Hunter API 密钥
  │   └── subfinder-config.yaml # Subfinder 各平台 API 凭据
  └── external/               # 运行时中间文件目录

## 快速开始

  1. 准备目标文件 targets.txt，每行一个目标（域名 / IP / CIDR）：

     example.com
     1.2.3.4
     10.0.0.0/24

  2. 首次运行，自动生成配置模板：

     ./baiyan -f targets.txt

     这会在 config/ 下生成配置文件模板，程序会退出提示你填写密钥。

  3. 编辑配置文件，填入你的 API 密钥：

     config/spaceConfig.ini:
       [fofa]
       email = your_email@example.com
       key = your_fofa_api_key
       num = 10000
       [quake]
       token = your_quake_token
       num = 500
       [hunter]
       key = your_hunter_api_key
       num = 1000

     config/subfinder-config.yaml:
       填入各子域数据源的 API 凭据（BinaryEdge, Censys, CertSpotter 等）

  4. 重新运行，开始扫描：

     ./baiyan -f targets.txt

## 命令行参数

  -f, --file <path>           目标文件路径 (与 --icp / -c 二选一)
  --icp <备案号|文件>           备案查询模式：传单个备案号字符串，或含备案号(每行一个)的文件路径。
                               独立运行，用 FOFA/Quake/Hunter 查 icp，汇总去重主域输出 beian<时间戳>.txt
  -c, --company <公司名|文件>   公司名查询模式：传公司名，或含公司名(每行一个)的文件路径。
                               走 ICP_Query(工信部) 查备案，输出 beianhao.txt(主备案号去重) + domain.txt(域名+规范化IP)
                               配合 --deep 可经风鸟(riskbird)扩张子公司/孙公司，每个子公司同样查备案
  --deep <n>                   -c 子公司扩张深度：0=仅母公司(默认)，1=+子公司，2=+孙公司，3=+曾孙（≥1 需风鸟 cookie）
  --ratio <n>                  -c 投资占比/控股下限(%)：仅投资比例≥此值的关联公司才视为子公司(默认 100=全资；51=控股线)
  --fast                       精选端口模式 (子域只扫精选 web 端口，比默认快；默认 -f 走全端口)
  --certscan                   开启证书关联 IP 扫描 (查询 TLS 证书中关联的 IP)
  --dirscan                    开启目录扫描
  --nofinger                   关闭最后的指纹探测 (observer_ward)
  -t, --threads <n>            HTTP 探活并发数 (默认 300)
  --mc, --masscan-concurrency <n>   masscan 端口扫描并发数 (默认 1)
  --root <path>                项目根目录 (默认当前目录 .)

## 使用示例

  # 基础扫描（子域收集 + 端口扫描 + HTTP 探活 + 指纹识别）
  ./baiyan -f targets.txt

  # 精选端口模式（子域只扫精选 web 端口，比默认快）
  ./baiyan -f targets.txt --fast

  # 开启目录扫描 + 证书关联 IP
  ./baiyan -f targets.txt --dirscan --certscan

  # 关闭指纹探测
  ./baiyan -f targets.txt --nofinger

  # 调整并发数
  ./baiyan -f targets.txt -t 500 --mc 4

  # 备案查询（独立模式，单个备案号）
  ./baiyan -icp "浙ICP备08009355号"

  # 备案查询（批量，文件每行一个备案号）
  ./baiyan -icp beians.txt

  # 公司名查询（独立模式，生成 beianhao.txt + domain.txt）
  ./baiyan -c 爱仕达股份有限公司
  # 公司名查询（批量，文件每行一个公司名）
  ./baiyan -c companies.txt

  # 公司名 + 子公司扩张（母公司 + 全资子公司，需风鸟 cookie）
  ./baiyan -c 爱仕达股份有限公司 --deep 1
  # 扩到孙公司，且只要控股≥51%的关联公司
  ./baiyan -c 爱仕达股份有限公司 --deep 2 --ratio 51

## 输出

  扫描完成后，在项目根目录下生成带时间戳的 XLSX 文件：

     result_20260616_143025.xlsx

  包含 5 个 Sheet：
    - 子域名      → 所有发现的子域名列表
    - URL         → 所有有效的 HTTP/HTTPS URL
    - title&指纹识别 → URL + 应用名称 + 响应长度 + 状态码 + 标题 + 优先级
    - 目录扫描     → 目录扫描发现的面板/后台路径
    - c段统计     → 域名-C段-命中次数的统计

  中间数据保存在 external/ 目录下，支持断点续扫。

  备案查询模式 (--icp) 独立于上述扫描流程，运行后在项目根目录生成：

     beian20260629_153000.txt

  内容为 FOFA/Quake/Hunter 三引擎汇总、去重后的主域列表，每行一个。
  任一引擎不可用 (宕机/余额不足/key 缺失) 自动跳过，不影响其余引擎。

## ================================================================
##  编译指南
## ================================================================

### 依赖环境

  - Go 1.19+
  - 目标平台需有 libpcap（masscan 依赖），Linux 下安装: apt-get install libpcap-dev

### 编译步骤

  本项目采用 embed 方式将 lib/ 和 config 模板嵌入二进制中，编译命令如下：

    # 1. 先复制 lib/ 到 embed 目录
    rm -rf internal/baiyan/lib
    cp -r lib internal/baiyan/lib

    # 2. 编译
    go build -o baiyan ./cmd/baiyan/

    # 3. 清理 embed 目录（避免提交到 git）
    rm -rf internal/baiyan/lib

### 各平台编译命令

  # ——— macOS (amd64) ———
  GOOS=darwin GOARCH=amd64 go build -o baiyan-darwin-amd64 ./cmd/baiyan/

  # ——— macOS (arm64 / Apple Silicon) ———
  GOOS=darwin GOARCH=arm64 go build -o baiyan-darwin-arm64 ./cmd/baiyan/

  # ——— Linux (amd64) ———
  GOOS=linux GOARCH=amd64 go build -o baiyan-linux-amd64 ./cmd/baiyan/

  # ——— Linux (arm64) ———
  GOOS=linux GOARCH=arm64 go build -o baiyan-linux-arm64 ./cmd/baiyan/

  # ——— Windows (amd64) ———
  GOOS=windows GOARCH=amd64 go build -o baiyan-windows-amd64.exe ./cmd/baiyan/

  # ——— Windows (arm64) ———
  GOOS=windows GOARCH=arm64 go build -o baiyan-windows-arm64.exe ./cmd/baiyan/

  注: Windows 下 masscan 等外部工具不可用，仅编译不保证运行。

### 一键编译脚本

  在项目根目录创建编译脚本（需先在 lib/ 所在目录运行）：

    #!/bin/bash
    set -e

    # 准备 embed 资源
    rm -rf internal/baiyan/lib
    cp -r lib internal/baiyan/lib

    # 编译所有平台
    PLATFORMS=(
      "darwin/amd64"
      "darwin/arm64"
      "linux/amd64"
      "linux/arm64"
      "windows/amd64"
    )

    for PLATFORM in "${PLATFORMS[@]}"; do
      GOOS="${PLATFORM%/*}"
      GOARCH="${PLATFORM#*/}"
      EXT=""
      if [ "$GOOS" = "windows" ]; then EXT=".exe"; fi
      echo "编译: $GOOS/$GOARCH -> baiyan-${GOOS}-${GOARCH}${EXT}"
      GOOS=$GOOS GOARCH=$GOARCH go build -o "baiyan-${GOOS}-${GOARCH}${EXT}" ./cmd/baiyan/
    done

    # 清理
    rm -rf internal/baiyan/lib
    echo "编译完成。"

## 注意事项

  1. **masscan 需要 root 权限** — 如果非 root 运行，端口扫描可能失败。
     解决办法: sudo ./baiyan -f targets.txt

  2. **首次运行**必须填写 config/ 下的 API 密钥，否则 FOFA / Quake / Subfinder 来源不可用。

  3. **断点续扫** — 程序意外中断后，使用相同参数重新运行会自动从断点继续。

  4. **lib/ 目录** — 开发时 lib/ 已经存在于项目根目录，编译出的二进制在运行时
     会自动将嵌入的 lib/ 解压到 --root 指定目录。如果 lib/ 已存在则跳过解压。

  5. 默认 -f 对非 CDN、非 mail/mx/smtp 等前缀的子域跑 masscan 全端口扫描；--fast 改用精选 web 端口，更快。

  6. DNS 解析使用阿里 DNS (223.5.5.5) TCP 连接，绕过 systemd-resolved 的 UDP 劫持。
