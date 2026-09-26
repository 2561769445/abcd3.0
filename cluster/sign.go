package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SignCtrl 控制指令签名: HMAC-SHA256(secret, action|taskID|cmd|session|execID|timeout)。
// master下发/节点校验共用本实现保证口径一致。
// secret为空返回空串=不签名(明文兼容模式, 供升级窗口期/未配置场景)。
func SignCtrl(secret string, cm *CtrlMessage) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s|%s|%s|%s|%s|%d", cm.Action, cm.TaskID, cm.Cmd, cm.Session, cm.ExecID, cm.Timeout)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCtrlSig 节点侧验签: secret为空=明文兼容放行(旧master/未配置);
// 非空则强制校验 — Redis密码泄露不再是exec任意命令的单点防线(纵深防御)。
func VerifyCtrlSig(secret string, cm *CtrlMessage) bool {
	if secret == "" {
		return true
	}
	want := SignCtrl(secret, cm)
	return hmac.Equal([]byte(want), []byte(cm.Sig))
}
