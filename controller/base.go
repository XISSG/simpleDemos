package controller

type IAlgorithm interface {
	Encrypt() //加密函数接口
	Decrypt() //解密函数接口
}

type DefaultAlgorithm struct {
}

func (dal DefaultAlgorithm) Encrypt() {

}

func (dal DefaultAlgorithm) Decrypt() {

}

type AlgrithomManager struct {
	algorithm IAlgorithm
}

func (gor *AlgrithomManager) SetAlgorithm(algorithm IAlgorithm) {
	gor.algorithm = algorithm
}

const (
	encryptMode = "encrypt"
	decryptMode = "decrypt"
)

func (gor *AlgrithomManager) RunAlgorithm(runMode string) {
	switch runMode {
	case encryptMode:
		gor.algorithm.Encrypt()
	case decryptMode:
		gor.algorithm.Decrypt()
	}
}
