package protocol

import (
	"crypto/md5"
	"testing"
	"time"
)

func TestReadAESCBCCodec(t *testing.T) {
	var plainStr = `GET / HTTP/1.1
Host: fanyi.baidu.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Cookie: BAIDUID=09E9ADE80D9692D307E588ECCE534747:FG=1; BIDUPSID=DC178E26B0465BABBFEE2539E956659B; PSTM=1522207301; locale=zh; Hm_lvt_64ecd82404c51e03dc91cb9e8c025574=1525666649,1525753690,1525852181,1525922327; from_lang_often=%5B%7B%22value%22%3A%22jp%22%2C%22text%22%3A%22%u65E5%u8BED%22%7D%2C%7B%22value%22%3A%22zh%22%2C%22text%22%3A%22%u4E2D%u6587%22%7D%2C%7B%22value%22%3A%22en%22%2C%22text%22%3A%22%u82F1%u8BED%22%7D%5D; to_lang_often=%5B%7B%22value%22%3A%22en%22%2C%22text%22%3A%22%u82F1%u8BED%22%7D%2C%7B%22value%22%3A%22zh%22%2C%22text%22%3A%22%u4E2D%u6587%22%7D%5D; REALTIME_TRANS_SWITCH=1; FANYI_WORD_SWITCH=1; HISTORY_SWITCH=1; SOUND_SPD_SWITCH=1; SOUND_PREFER_SWITCH=1; Hm_lpvt_64ecd82404c51e03dc91cb9e8c025574=1525922327
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
`
	var plainBs = []byte(plainStr)
	var inLen = len(plainBs)
	t.Logf("plainBs len = %d", inLen)

	var keyBs = md5.Sum([]byte(time.Now().String()))
	var cipherBs, enErr = AESCBCCodec(keyBs[:], plainBs, true)
	if nil != enErr {
		t.Error(enErr.Error())
	}
	t.Logf("cipherBs len = %d", len(cipherBs))

	var plain1Bs, deErr = AESCBCCodec(keyBs[:], cipherBs, false)
	if nil != deErr {
		t.Error(deErr.Error())
	}
	if plainStr == string(plain1Bs) {
		t.Log("AESCBCCodec success")
	} else {
		t.Error("AESCBCCodec fail")
	}
}
