// SPDX-License-Identifier: AGPL-3.0-or-later

package ctxlogrus

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

var (
	nullLogger = &logrus.Logger{
		Out:       ioutil.Discard,
		Formatter: new(logrus.TextFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.PanicLevel,
	}
)
