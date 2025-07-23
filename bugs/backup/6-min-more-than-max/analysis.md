# Root cause

The `min` and `max` field is more conservative than the `var_off`,
which means the latter has wider range than the former.
For example,
the min and max value at 5 is [884670597, 900354100],
while min and max inferred from the var_off is [872415232, 905928639].

In this case, when it goes to the jmp instruction,
it uses the var_off (wider range) to **and** with 0x894b6a55,
and founds it's possible to reach two branches.
However, the real range (the narrow one) can only goes to the "goto branch".

var_off: | 872415232 | A: X & 0x894b6a55 == 0  |             ...                   | 905928639 |
min_max: |	                                   | 884670597 | ... |  900354100                  |

Afterwards, it calculates the new var_off according to 0x894b6a55,
old var_off and "and" operation.
In this case, the new var_off will express the range **A** [a1, a2],
which doesn't have the intersection with the old min and max [b1, b2].
Thus, the new range will be [b1=max(a1,b1), a2=min(a2,b2)], but b1 > a2.

```c
5: (bc) w0 = w5
R0_w=scalar(id=1,smin=umin=smin32=umin32=884670597,smax=umax=smax32=umax32=900354100,var_off=(0x34000000; 0x1ff5fbf))
R5_w=scalar(id=1,smin=umin=smin32=umin32=884670597,smax=umax=smax32=umax32=900354100,var_off=(0x34000000; 0x1ff5fbf))
6: (46) if w0 & 0x894b6a55 goto pc+7
R0_w=scalar(id=1,smin=umin=smin32=umin32=884670597,smax=umax=smax32=umax32=884217258,var_off=(0x34b00000; 0x415aa))
```
