package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"baiyan/internal/baiyan"
)

func main() {
	var opts baiyan.Options

	flag.StringVar(&opts.TargetsFile, "file", "", "目标文件路径")
	flag.StringVar(&opts.TargetsFile, "f", "", "目标文件路径")
	flag.StringVar(&opts.ICP, "icp", "", "备案查询模式：传备案号字符串，或含备案号(每行一个)的文件路径")
	flag.StringVar(&opts.Company, "c", "", "公司名查询模式（-c 为 --company 简写）：传公司名，或含公司名(每行一个)的文件路径；生成 beianhao.txt + domain.txt")
	flag.StringVar(&opts.Company, "company", "", "公司名查询模式：传公司名或含公司名的文件；生成 beianhao.txt + domain.txt（--deep 可扩张子公司）")
	flag.IntVar(&opts.Deep, "deep", 0, "-c 子公司扩张深度：0=仅母公司，1=+子公司，2=+孙公司，3=+曾孙（默认 0；≥1 需风鸟 cookie）")
	flag.IntVar(&opts.Ratio, "ratio", 100, "-c 投资占比/控股下限(%)：仅投资比例≥此值的关联公司才视为子公司/孙公司（默认 100=全资）")
	flag.BoolVar(&opts.CertScan, "certscan", false, "开启证书关联 IP 扫描")
	flag.BoolVar(&opts.DirScan, "dirscan", false, "开启目录扫描")
	flag.BoolVar(&opts.FastScan, "fast", false, "精选端口模式：子域只扫精选 web 端口(更快)；不加则默认 -f 走全端口")
	flag.BoolVar(&opts.NoFinger, "nofinger", false, "关闭最后的指纹探测")
	flag.IntVar(&opts.Threads, "threads", 300, "线程数")
	flag.IntVar(&opts.Threads, "t", 300, "线程数")
	flag.IntVar(&opts.MasscanConcurrency, "mc", 1, "masscan 并发数")
	flag.IntVar(&opts.MasscanConcurrency, "masscan-concurrency", 1, "masscan 并发数")
	flag.StringVar(&opts.RootDir, "root", ".", "项目根目录")
	flag.Parse()

	if opts.TargetsFile == "" && opts.ICP == "" && opts.Company == "" {
		fmt.Fprintln(os.Stderr, "缺少必填参数: --file 或 --icp 或 --c")
		flag.Usage()
		os.Exit(2)
	}

	app, err := baiyan.New(opts)
	if err != nil {
		if errors.Is(err, baiyan.ErrConfigGenerated) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	if err := app.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "运行失败: %v\n", err)
		os.Exit(1)
	}
}
