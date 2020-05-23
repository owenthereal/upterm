# Emitter [![wercker status](https://app.wercker.com/status/e5a44746dc89b513ed28e8a18c5c05c2/s "wercker status")](https://app.wercker.com/project/bykey/e5a44746dc89b513ed28e8a18c5c05c2) [![Coverage Status](https://coveralls.io/repos/olebedev/emitter/badge.svg?branch=HEAD&service=github)](https://coveralls.io/github/olebedev/emitter?branch=HEAD) [![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/olebedev/emitter)

The emitter package implements a channel-based pubsub pattern. The design goals are to use Golang concurrency model instead of flat callbacks and to design a very simple API that is easy to consume.
## Why?
Go has expressive concurrency model but nobody uses it properly for pubsub as far as I can tell (in the year 2015). I implemented my own solution as I could not find any other that meets my expectations. Please, read [this article](#) for more information.


## What it does?

- [sync/async event emitting](#flags)
- [predicates/middlewares](#middlewares)
- [bi-directional wildcard](#wildcard)
- [discard emitting if needed](#cancellation)
- [merge events from different channels](#groups)
- [shallow on demand type casting](#event)
- [work with callbacks(traditional way)](#callbacks-only-usage)


## Brief example

```go
e := &emitter.Emitter{}
go func(){
	<-e.Emit("change", 42) // wait for the event sent successfully
	<-e.Emit("change", 37)
	e.Off("*") // unsubscribe any listeners
}()

for event := range e.On("change") {
	// do something with event.Args
	println(event.Int(0)) // cast the first argument to int
}
// listener channel was closed
```

## Constructor
`emitter.New` takes a `uint` as the first argument to indicate what buffer size should be used for listeners. It is also possible to change the buffer capacity during runtime using the following code: `e.Cap = 10`.

By default, the emitter uses one goroutine per listener to send an event. You can change that behavior from asynchronous to synchronous by passing `emitter.Sync` flag as shown here: `e.Use("*", emitter.Sync)`. I recommend specifying middlewares(see [below](#middlewares)) for the emitter at the begining.

## Wildcard
The package allows publications and subscriptions with wildcard. This feature is based on `path.Match` function.

Example:

```go
go e.Emit("something:special", 42)
event := <-e.Once("*") // search any events
println(event.Int(0)) // will print 42

// or emit an event with wildcard path
go e.Emit("*", 37) // emmit for everyone
event := <-e.Once("something:special")
println(event.Int(0)) // will print 37
```

Note that the wildcard uses `path.Match`, but the lib does not return errors related to parsing for this is not the main feature. Please check the topic specifically via `emitter.Test()` function.

## Middlewares
An important part of pubsub package is the predicates. It should be allowed to skip some events. Middlewares address this problem.
The middleware is a function that takes a pointer to the `Event` as its first argument. A middleware is capable of doing the following items:

1. It allows you to modify an event.
2. It allows skipping the event emitting if needed.
3. It also allows modification of the event's arguments.
4. It allows you to specify the mode to describe how exactly an event should be emitted(see [below](#flags)).

There are two ways to add middleware into the event emitting flow:

- via .On("event", middlewares...)
- via .Use("event", middlewares...)

The first one add middlewares only for a particular listener, while the second one adds middlewares for all events with a given topic.

For example:
```go
// use synchronous mode for all events, it also depends
// on the emitter capacity(buffered/unbuffered channels)
e.Use("*", emitter.Sync)
go e.Emit("something:special", 42)

// define predicate
event := <-e.Once("*", func(ev *emitter.Event){
	if ev.Int(0) == 42 {
	    // skip sending
		ev.Flags = ev.Flags | emitter.FlagVoid
	}
})
panic("will never happen")
```


## Flags
Flags needs to describe how exactly the event should be emitted. The available options are listed [here](https://godoc.org/github.com/olebedev/emitter#Flag).

Every event(`emitter.Event`) has a field called`.Flags` that contains flags as a binary mask.
Flags can be set only via middlewares(see above).

There are several predefined middlewares to set needed flags:

- [`emitter.Once`](https://godoc.org/github.com/olebedev/emitter#Once)
- [`emitter.Close`](https://godoc.org/github.com/olebedev/emitter#Close)
- [`emitter.Void`](https://godoc.org/github.com/olebedev/emitter#Void)
- [`emitter.Skip`](https://godoc.org/github.com/olebedev/emitter#Skip)
- [`emitter.Sync`](https://godoc.org/github.com/olebedev/emitter#Sync)
- [`emitter.Reset`](https://godoc.org/github.com/olebedev/emitter#Reset)

You can chain the above flags as shown below:
```go
e.Use("*", emitter.Void) // skip sending for any events
go e.Emit("surprise", 65536)
event := <-e.On("*", emitter.Reset, emitter.Sync, emitter.Once) // set custom flags for this listener
pintln(event.Int(0)) // prints 65536
```

## Cancellation
Golang provides developers with a powerful control for its concurrency flow. We know the state of a channel and whether it would block a go routine or not. So, by using this language construct, we can discard any emitted event. It's a good practice to design your application with timeouts so that you cancel the operations if needed as shown below:

Assume you have time out to emit the events:
```go
done := e.Emit("broadcast", "the", "event", "with", "timeout")

select {
case <-done:
	// so the sending is done
case <-time.After(timeout):
	// time is out, let's discard emitting
	close(done)
}
```

It's pretty useful to control any goroutines inside an emitter instance.

## Callbacks-only usage
using the emitter in more traditional way is possible, as well. If you don't need the async mode or you very attentive to the application resources, then the recipe is to use an emitter with zero capacity or to use `FlagVoid` to skip sending into the listener channel and use middleware as callback:

```go
e := &emitter.Emitter{}
e.Use("*", emitter.Void)

go e.Emit("change", "field", "value")
e.On("change", func(event *Event){
	// handle changes here
	field := event.String(0)
	value := event.String(1)
	// ...and so on
})
```

## Groups
Group merges different listeners into one channel.
Example:
```go
e1 := &emitter.Emitter{}
e2 := &emitter.Emitter{}
e3 := &emitter.Emitter{}

g := &emitter.Group{Cap: 1}
g.Add(e1.On("first"), e2.On("second"), e3.On("third"))

for event := g.On() {
	// handle the event
	// event has field OriginalTopic and Topic
}
```
Also you can combine several groups into one.

See the api [here](https://godoc.org/github.com/olebedev/emitter#Group).


## Event
Event is a struct that contains event [information](https://godoc.org/github.com/olebedev/emitter#Event). Also, th event has some helpers to cast various arguments into `bool`, `string`, `float64`, `int` by given argument index with an optional default value.

Example:
```go

go e.Emit("*", "some string", 42, 37.0, true)
event := <-e.Once("*")

first := event.String(0)
second := event.Int(1)
third := event.Float(2)
fourth := event.Bool(3)

// use default value if not exists
dontExists := event.Int(10, 64)
// or use dafault value if type don't match
def := event.Int(0, 128)

// .. and so on
```

## License
MIT
