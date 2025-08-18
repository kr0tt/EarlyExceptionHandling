# Early Exception Handling

This repo contains the examples of two tools that use `KiUserExceptionDispatcher` & `Wow64PrepareForException` for hooking and threadless process injection. You can read more about this [here](https://kr0tt.github.io/posts/early-exception-handling/).
## KiUserExceptionDispatcherStepOver

This example uses `KiUserExceptionDispatcher` & `Wow64PrepareForException` and hardware breakpoints to step over inline hooks in `ntdll.dll`. Please note that the EDR's hook offset from the NT function stub entry is hardcoded and so are the `SSN`s of the NT functions.
## KiUserExceptionDispatcherInjection

This example uses `KiUserExceptionDispatcher` & `Wow64PrepareForException` for threadless process injection. It creates a suspended process, injects a payload and shellcode stub and finally resumes the suspended process.  To raise an exception in the remote process, it can either set a hardware breakpoint on the remote thread or set a `PAGE_GUARD` on the remote process entry point.

To use it, simply:
```
.\KiUserExceptionDispatcherInjection.exe < YOUR SHELLCODE > < hwbp | page_guard>
```

## Resources

The following are various resources that I used while writing the blog post and examples. This is by no means extensive, I definitely missed someone or some project :(

- [Intel Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Skywing's kernel mode to user mode callbacks series](http://www.nynaeve.net/?p=200)
- [Applied Reverse Engineering: Exceptions and Interrupts](https://revers.engineering/applied-re-exceptions/)
- [OSDev - Interrupt Descriptor Table](https://wiki.osdev.org/Interrupt_Descriptor_Table)
- [Axel "0vercl0k" Souchet's blog - Having a look at the Windows' User/Kernel exceptions dispatcher](https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/)
- [modexp - WOW64 Callback Table](https://modexp.wordpress.com/2023/04/19/finding-the-wow64-callback-table/)
- [Joshua Magri - You just got vectored](https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection)
- [mannyfreddy - Fun with Exception Handlers](https://mannyfreddy.gitbook.io/ya-boy-manny#fun-with-exception-handlers)
- [Outflank - Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)
