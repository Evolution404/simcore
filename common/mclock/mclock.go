// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package mclock is a wrapper for a monotonic clock source
package mclock

import (
	"time"

	_ "unsafe" // for go:linkname
)

//go:noescape
//go:linkname nanotime runtime.nanotime
func nanotime() int64

// AbsTime represents absolute monotonic time.
type AbsTime int64

// Now returns the current absolute monotonic time.
// 获取当前系统启动到现在的绝对时间
func Now() AbsTime {
	return AbsTime(nanotime())
}

// 对AbsTime实现加减操作
// Add returns t + d as absolute time.
func (t AbsTime) Add(d time.Duration) AbsTime {
	return t + AbsTime(d)
}

// Sub returns t - t2 as a duration.
// 减法返回time.Duration对象
func (t AbsTime) Sub(t2 AbsTime) time.Duration {
	return time.Duration(t - t2)
}

// The Clock interface makes it possible to replace the monotonic system clock with
// a simulated clock.
// System对象和Simulated对象实现了这个接口
// System使用的系统内置接口
// Simulated应该是重写了一个
type Clock interface {
	Now() AbsTime
	Sleep(time.Duration)
	NewTimer(time.Duration) ChanTimer
	// After返回一个管道,当输入时间到了管道内输出结束时间
	After(time.Duration) <-chan AbsTime
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a cancellable event created by AfterFunc.
// Clock.AfterFunc返回的对象
type Timer interface {
	// Stop cancels the timer. It returns false if the timer has already
	// expired or been stopped.
	Stop() bool
}

// ChanTimer is a cancellable event created by NewTimer.
// systemTimer和simTimer实现了这个接口
type ChanTimer interface {
	Timer

	// The channel returned by C receives a value when the timer expires.
	// 返回一个只读管道,当ChanTimer时间到了就会返回向管道输入一个值
	C() <-chan AbsTime
	// Reset reschedules the timer with a new timeout.
	// It should be invoked only on stopped or expired timers with drained channels.
	Reset(time.Duration)
}

// System implements Clock using the system clock.
// 使用系统内置方法实现了Clock接口的5个函数
type System struct{}

// Now returns the current monotonic time.
func (c System) Now() AbsTime {
	return Now()
}

// Sleep blocks for the given duration.
func (c System) Sleep(d time.Duration) {
	time.Sleep(d)
}

// NewTimer creates a timer which can be rescheduled.
// 返回一个ChanTimer,等待指定的d时间后timer.C返回的管道会输出结束时的时间
func (c System) NewTimer(d time.Duration) ChanTimer {
	ch := make(chan AbsTime, 1)
	// 等待d时间后就会向ch中发送当前时间
	t := time.AfterFunc(d, func() {
		// This send is non-blocking because that's how time.Timer
		// behaves. It doesn't matter in the happy case, but does
		// when Reset is misused.
		select {
		case ch <- c.Now():
		default:
		}
	})
	return &systemTimer{t, ch}
}

// After returns a channel which receives the current time after d has elapsed.
// 等待指定时间管道可以读出时间
func (c System) After(d time.Duration) <-chan AbsTime {
	ch := make(chan AbsTime, 1)
	time.AfterFunc(d, func() { ch <- c.Now() })
	return ch
}

// AfterFunc runs f on a new goroutine after the duration has elapsed.
// 等待指定时间执行函数
func (c System) AfterFunc(d time.Duration, f func()) Timer {
	return time.AfterFunc(d, f)
}

// 实现了Timer接口
type systemTimer struct {
	*time.Timer
	ch <-chan AbsTime
}

func (st *systemTimer) Reset(d time.Duration) {
	st.Timer.Reset(d)
}

func (st *systemTimer) C() <-chan AbsTime {
	return st.ch
}
