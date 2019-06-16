#!/usr/bin/python
import frida

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

pid = frida.spawn(["sample/simple-if-statement-tree", "aaa"])
session = frida.attach(pid)

script = session.create_script("""'use strict';

rpc.exports.enumerateModules = function () {
  return Process.enumerateModulesSync();
};

function callback(details) {
  console.dir(details);
}

rpc.exports.setExceptionHandler = function () {

  Process.setExceptionHandler(callback);
}
""")
script.on("message", on_message)
script.load()

print([m["name"] for m in script.exports.enumerate_modules()])

script.exports.setExceptionHandler()