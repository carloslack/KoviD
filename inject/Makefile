# turn off ring buffer debug:
# $ DEPLOY=1 make

LD=$(shell which ld)
AS=$(shell which as)

all:
	# kovid as include file
	as -o kv_incbin.o kv_incbin.S
	ld -o kv_incbin kv_incbin.o
	# kovid embedded
	as -o kv_embed.o kv_embed.S
	ld -o kv_embed kv_embed.o

clean:
	@rm -fv *.o kv_incbin kv_embed

