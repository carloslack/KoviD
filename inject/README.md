##  1 Build steps

### 1.1 Build KoviD

        cd ../ && PROCNAME=kovid make && make strip && cd -

## 2 Build payload

        ./update.sh && make

## 3 Test

        sudo ./kv_embed ; dmesg
