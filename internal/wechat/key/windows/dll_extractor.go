package windows

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/util"
)

// DLL函数定义
var (
	modwxkey *windows.LazyDLL

	procInitializeHook   *windows.LazyProc
	procPollKeyData      *windows.LazyProc
	procGetStatusMessage *windows.LazyProc
	procCleanupHook      *windows.LazyProc
	procGetLastErrorMsg  *windows.LazyProc

	dllAvailable = false // 标记DLL是否可用
)

// DLLExtractor 使用wx_key.dll的密钥提取器
type DLLExtractor struct {
	validator *decrypt.Validator
	mu        sync.Mutex
	initialized bool
	pid        uint32
	lastKey   string // 记录上次获取的密钥，用于简单去重
	logger    *util.DLLLogger // DLL日志记录器
}

// init 初始化DLL函数
func init() {
	// 加载DLL - 使用相对路径
	dllPath := "lib/windows_x64/wx_key.dll"
	modwxkey = windows.NewLazyDLL(dllPath)

	// 尝试加载DLL，检查是否可用
	err := modwxkey.Load()
	if err != nil {
		log.Debug().Err(err).Msg("wx_key.dll 加载失败，将使用原生方式")
		dllAvailable = false
		return
	}

	// 获取函数指针
	procInitializeHook = modwxkey.NewProc("InitializeHook")
	procPollKeyData = modwxkey.NewProc("PollKeyData")
	procGetStatusMessage = modwxkey.NewProc("GetStatusMessage")
	procCleanupHook = modwxkey.NewProc("CleanupHook")
	procGetLastErrorMsg = modwxkey.NewProc("GetLastErrorMsg")

	// 检查所有函数是否都成功获取
	if procInitializeHook != nil && procPollKeyData != nil && procGetStatusMessage != nil &&
		procCleanupHook != nil && procGetLastErrorMsg != nil {
		dllAvailable = true
		log.Debug().Msg("wx_key.dll 加载成功，将使用DLL方式获取密钥")
	} else {
		dllAvailable = false
		log.Debug().Msg("wx_key.dll 函数获取失败，将使用原生方式")
	}
}

// IsDLLAvailable 检查DLL是否可用
func IsDLLAvailable() bool {
	return dllAvailable
}

// NewDLLV4Extractor 创建使用DLL的V4密钥提取器
func NewDLLV4Extractor() *DLLExtractor {
	return &DLLExtractor{
		logger: util.GetDLLLogger(),
	}
}

// Extract 从进程中提取密钥（使用DLL方式）
func (e *DLLExtractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	// 即使状态是offline（未登录），也允许尝试初始化DLL
	// 因为DLL方式可以在用户登录后拦截密钥
	if proc.Status == model.StatusOffline {
		log.Info().Msg("微信进程存在但未登录，将尝试初始化DLL，请登录微信后操作")
		// 不返回错误，继续执行
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 清理之前的初始化（如果存在）
	if e.initialized {
		e.cleanup()
	}

	// 初始化DLL
	if err := e.initialize(proc.PID); err != nil {
		return "", "", err
	}

	// 确保无论成功失败都清理
	// 注意：这里使用defer确保cleanup在函数返回前执行
	defer func() {
		if e.initialized {
			e.cleanup()
		}
	}()

	// 轮询获取密钥
	return e.pollKeys(ctx, proc.Version)
}

// initialize 初始化DLL Hook
func (e *DLLExtractor) initialize(pid uint32) error {
	// 调用InitializeHook
	ret, _, err := procInitializeHook.Call(uintptr(pid))
	if ret == 0 {
		// 获取错误信息
		errorMsg := e.getLastError()

		// 记录错误日志
		if e.logger != nil {
			e.logger.LogInitialization(pid, false, errorMsg)
		}

		if errorMsg != "" {
			return fmt.Errorf("初始化DLL失败: %s", errorMsg)
		}
		if err != nil {
			return fmt.Errorf("初始化DLL失败: %v", err)
		}
		return fmt.Errorf("初始化DLL失败")
	}

	e.initialized = true
	e.pid = pid

	// 记录成功日志
	if e.logger != nil {
		e.logger.LogInitialization(pid, true, "")
		e.logger.LogInfo(fmt.Sprintf("DLL初始化成功，PID: %d", pid))
	}

	log.Debug().Msgf("DLL初始化成功，PID: %d", pid)
	return nil
}

// pollKeys 轮询获取密钥
func (e *DLLExtractor) pollKeys(ctx context.Context, version int) (string, string, error) {
	if !e.initialized {
		return "", "", fmt.Errorf("DLL未初始化")
	}

	// 设置超时时间 - 改为30秒
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var dataKey, imgKey string
	loginPromptShown := false // 标记是否已显示登录提示
	pollCount := 0            // 轮询计数器

	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-timeout:
			// 检查是否获取到了数据密钥
			if dataKey != "" {
				// 获取到了数据密钥，但没有获取到图片密钥
				warningMsg := "30秒轮询结束，已获取数据库密钥，但未获取到图片密钥\n" +
					"注意：对于微信V4，图片密钥可能不是必需的，或者需要其他方式获取\n" +
					"数据库密钥: " + dataKey
				log.Warn().Msg("30秒轮询结束，已获取数据库密钥，但未获取到图片密钥")
				log.Warn().Msg("注意：对于微信V4，图片密钥可能不是必需的，或者需要其他方式获取")
				log.Warn().Msg("数据库密钥: " + dataKey)

				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogWarning(warningMsg)
				}

				// 返回数据库密钥，图片密钥为空
				return dataKey, "", nil
			} else {
				// 没有获取到任何密钥
				errorMsg := "获取密钥超时（30秒）！可能的原因：\n" +
					"1. 微信未登录 - 请登录微信\n" +
					"2. 未触发数据库读取 - 请打开聊天窗口并查看历史消息\n" +
					"3. DLL Hook失败 - 检查日志文件查看详细错误\n" +
					"4. 微信版本不受支持 - 当前支持: 4.0.x 及以上 4.x 版本"
				log.Error().Msg("获取密钥超时（30秒）！可能的原因：")
				log.Error().Msg("1. 微信未登录 - 请登录微信")
				log.Error().Msg("2. 未触发数据库读取 - 请打开聊天窗口并查看历史消息")
				log.Error().Msg("3. DLL Hook失败 - 检查日志文件查看详细错误")
				log.Error().Msg("4. 微信版本不受支持 - 当前支持: 4.0.x 及以上 4.x 版本")

				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogError(errorMsg)
				}
				return "", "", fmt.Errorf("获取密钥超时（30秒，请查看上方错误提示）")
			}
		case <-ticker.C:
			pollCount++

			// 尝试获取密钥
			key, err := e.pollKeyData()
			if err != nil {
				errorMsg := fmt.Sprintf("轮询密钥失败: %v", err)
				log.Err(err).Msg("轮询密钥失败")
				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogError(errorMsg)
				}
				continue
			}

			if key != "" && key != e.lastKey {
				// 简单去重：避免重复处理相同的密钥
				e.lastKey = key

				// 验证密钥类型
				keyBytes, err := hex.DecodeString(key)
				if err != nil {
					errorMsg := fmt.Sprintf("解码密钥失败: %v", err)
					log.Err(err).Msg("解码密钥失败")
					// 记录到日志文件
					if e.logger != nil {
						e.logger.LogError(errorMsg)
					}
					continue
				}

				// 检查是否是数据库密钥
				if e.validator != nil && e.validator.Validate(keyBytes) {
					if dataKey == "" {
						dataKey = key
						msg := "通过DLL找到数据库密钥: " + key
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, key, "数据库")
							e.logger.LogInfo(msg)
						}
					}
				} else if e.validator == nil {
					// 验证器为nil时，根据密钥长度判断
					// 数据库密钥通常是32字节（64字符HEX字符串）
					// 图片密钥通常是16字节（32字符HEX字符串）
					if len(key) == 64 && dataKey == "" {
						dataKey = key
						msg := "通过DLL找到数据库密钥（无验证）: " + key
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, key, "数据库")
							e.logger.LogInfo(msg)
						}
					} else if len(key) == 32 && imgKey == "" {
						imgKey = key
						msg := "通过DLL找到图片密钥（无验证）: " + imgKey
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, imgKey, "图片")
							e.logger.LogInfo(msg)
						}
					}
				}

				// 检查是否是图片密钥（取前16字节）
				if e.validator != nil && e.validator.ValidateImgKey(keyBytes) {
					if imgKey == "" {
						imgKey = key[:32] // 16字节的HEX字符串是32个字符
						msg := "通过DLL找到图片密钥: " + imgKey
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, imgKey, "图片")
							e.logger.LogInfo(msg)
						}
					}
				}

				// 如果两个密钥都找到了，返回
				if dataKey != "" && imgKey != "" {
					return dataKey, imgKey, nil
				}

				// 对于微信V3，只需要数据库密钥
				if version == 3 && dataKey != "" {
					return dataKey, "", nil
				}

			} else {
				// 没有获取到密钥，每5秒显示一次操作提示
				// 每100ms轮询一次，50次轮询 = 5秒
				if !loginPromptShown && pollCount%50 == 0 {
					msg := "等待获取密钥... 请按以下步骤操作：\n" +
						"1. 确保微信已登录（不能停留在登录界面）\n" +
						"2. 打开任意聊天窗口\n" +
						"3. 向上滚动查看历史消息（触发数据库读取）\n" +
						"4. 或者发送/接收一条新消息"
					log.Info().Msg("等待获取密钥... 请按以下步骤操作：")
					log.Info().Msg("1. 确保微信已登录（不能停留在登录界面）")
					log.Info().Msg("2. 打开任意聊天窗口")
					log.Info().Msg("3. 向上滚动查看历史消息（触发数据库读取）")
					log.Info().Msg("4. 或者发送/接收一条新消息")

					// 记录到日志文件
					if e.logger != nil {
						e.logger.LogInfo(msg)
					}
					loginPromptShown = true
				}
			}

			// 获取状态信息
			e.getStatusMessages()

			// 每10秒显示一次调试信息
			if pollCount%100 == 0 {
				debugMsg := fmt.Sprintf("轮询中... 已轮询 %d 次，已等待 %.1f 秒", pollCount, float64(pollCount)*0.1)
				log.Debug().Msg(debugMsg)

				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogDebug(debugMsg)
				}
			}
		}
	}
}

// pollKeyData 调用DLL的PollKeyData函数
func (e *DLLExtractor) pollKeyData() (string, error) {
	if !e.initialized {
		return "", fmt.Errorf("DLL未初始化")
	}

	// 分配缓冲区（至少65字节，建议128字节）
	buf := make([]byte, 128)
	ret, _, _ := procPollKeyData.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if ret == 0 {
		// 没有新密钥
		return "", nil
	}

	// 找到以null结尾的字符串
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			key := string(buf[:i])
			if key != "" {
				debugMsg := fmt.Sprintf("从DLL获取到密钥字符串: %s (长度: %d)", key, len(key))
				log.Debug().Msg(debugMsg)
				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogDebug(debugMsg)
				}
			}
			return key, nil
		}
	}

	key := string(buf)
	if key != "" {
		debugMsg := fmt.Sprintf("从DLL获取到密钥字符串(无null终止): %s (长度: %d)", key, len(key))
		log.Debug().Msg(debugMsg)
		// 记录到日志文件
		if e.logger != nil {
			e.logger.LogDebug(debugMsg)
		}
	}
	return key, nil
}

// getStatusMessages 获取DLL状态信息
func (e *DLLExtractor) getStatusMessages() {
	if !e.initialized {
		return
	}

	buf := make([]byte, 512)
	var level int32

	for {
		ret, _, _ := procGetStatusMessage.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&level)),
		)

		if ret == 0 {
			break
		}

		// 找到以null结尾的字符串
		var msg string
		for i := 0; i < len(buf); i++ {
			if buf[i] == 0 {
				msg = string(buf[:i])
				break
			}
		}

		if msg != "" {
			logLevel := "INFO"
			if level == 1 {
				logLevel = "SUCCESS"
			} else if level == 2 {
				logLevel = "ERROR"
			}
			log.Debug().Msgf("[DLL %s] %s", logLevel, msg)

			// 记录到日志文件
			if e.logger != nil {
				e.logger.LogStatus(int(level), msg)
			}
		}
	}
}

// getLastError 获取DLL最后错误信息
func (e *DLLExtractor) getLastError() string {
	ret, _, _ := procGetLastErrorMsg.Call()
	if ret == 0 {
		return ""
	}

	// 将指针转换为Go字符串
	errorMsgPtr := (*byte)(unsafe.Pointer(ret))
	if errorMsgPtr == nil {
		return ""
	}

	// 计算字符串长度
	length := 0
	for {
		if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(errorMsgPtr)) + uintptr(length))) == 0 {
			break
		}
		length++
		if length > 1024 {
			break
		}
	}

	if length == 0 {
		return ""
	}

	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(errorMsgPtr)) + uintptr(i)))
	}

	errorMsg := string(buf)

	// 记录错误信息到日志文件
	if e.logger != nil && errorMsg != "" {
		e.logger.LogError(errorMsg)
	}

	return errorMsg
}

// cleanup 清理DLL资源
func (e *DLLExtractor) cleanup() {
	if !e.initialized {
		return
	}

	procCleanupHook.Call()
	e.initialized = false
	e.lastKey = "" // 清理上次密钥记录

	// 记录清理日志
	if e.logger != nil {
		e.logger.LogCleanup()
	}

	log.Debug().Msg("DLL资源已清理")
}

// SearchKey 在内存中搜索密钥（DLL方式不支持此功能）
func (e *DLLExtractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	// DLL方式不支持直接内存搜索
	return "", false
}

// SetValidate 设置验证器
func (e *DLLExtractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}