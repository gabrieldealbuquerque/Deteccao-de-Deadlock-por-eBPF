# Mission Control — laboratório eBPF + TCP

Este repositório contém um exercício de laboratório em que duas aplicações em C abrem **duas conexões TCP cruzadas** (cada um escuta em uma porta e abre conexão de saída para a porta do outro) e, com as conexões em `ESTABLISHED`, entram as duas em `recv()` bloqueante sem que o outro lado envie dados — um **impasse de rede** clássico (cada extremo à espera de dados que nunca chegam).

O objetivo é mostrar como **eBPF** no kernel, acoplado à ponte Docker com **TC (Traffic Control)**, pode:

1. observar o tráfego entre os containers;
2. inferir inatividade prolongada de **carga útil TCP** (ausência de segmentos com payload de dados) após o handshake;
3. sinalizar o processo em **espaço de usuário** via **ring buffer**;
4. reescrever o segmento interceptado com **TCP RST+ACK** e ajuste de checksum com `bpf_l4_csum_replace`, para derrubar a conexão e destravar os `recv()`.

O *userspace* se comunica com o kernel pela **libbpf**: o `bpftool` gera o skeleton `deadlock_bpf.skel.h` a partir do *object* `deadlock_bpf.o` (mapas e *file descriptors* já tipados), e o *loader* usa essa API em C para carregar o programa, anexar o *hook* TC e fazer *poll* do ring buffer.

## Componentes

| Peça | Descrição |
|------|-----------|
| `app_a.c` / `app_b.c` | Servidores TCP (portas 8081 e 8082) e clientes do par; lógica de impasse; `SO_KEEPALIVE` e intervalos curtos para existir tráfego periódico (keepalives) na ponte; sem isso o TC quase não “vê” o tempo passar. |
| `deadlock_bpf.c` | Programa eBPF de tipo *scheduler* TC, seção `SEC("tc")`. Usa `vmlinux.h` (BTF do kernel), mapas (array de configuração, hash de estado, ring buffer) e helpers padrão (`bpf_l4_csum_replace`, `bpf_ringbuf_output`, `bpf_map_*`, `bpf_ktime_get_ns`, etc.). |
| `loader.c` | Carrega o *object* via skeleton `deadlock_bpf.skel.h`, preenche os IPs do par, cria o *hook* TC *ingress* na interface `br-*` da rede Docker, faz *poll* do ring buffer e trata sinais para *detach* e limpeza. |
| `docker-compose.yml` + `Dockerfile` | Apps em dois containers na faixa 172.28.0.0/16 (`mission_control_net`). |
| `Dockerfile.loader` | Imagem Ubuntu 22.04 com `clang`, `llvm`, `bpftool`, `libbpf-dev`, etc.; o serviço `ebpf_loader` monta o projeto em `/opt/mission`, usa `privileged`, `network_mode: host`, `pid: host` e volumes para BTF, `/sys/fs/bpf` e `/sys/kernel/debug`, e roda `make` / `./loader` no kernel do host. |
| `mission_control_lab.ipynb` | Fluxo com `docker compose` e `docker exec ebpf_loader …` (sem toolchain no host). |

O `Makefile` gera `vmlinux.h` a partir de `/sys/kernel/btf/vmlinux`, compila `deadlock_bpf.c` → `deadlock_bpf.o` com `clang` (*target bpf*), roda `bpftool gen skeleton` e linka o *loader* com **libbpf**, **libelf** e **zlib**. Isso pode rodar no host (se você tiver as ferramentas) ou **dentro** do container `ebpf_loader`, que é o caminho documentado no notebook.

## Dependências

**No host (Linux):** Docker / Docker Compose e kernel com BTF em `/sys/kernel/btf/vmlinux` (montado no `ebpf_loader` como somente leitura). Não é obrigatório instalar `clang`, `llvm` ou `bpftool` no host se você usar só o fluxo com `ebpf_loader`.

**Na imagem `Dockerfile.loader`:** `clang`, `llvm`, `make`, `gcc`, `pkg-config`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `bpftool`, `linux-tools-common`, `linux-tools-generic`.

**Na imagem das apps (`Dockerfile`):** `gcc` e *glibc* (Debian) para compilar `app_a` e `app_b`.

## Compilação

Fluxo recomendado (tudo via Compose + `ebpf_loader`):

```bash
docker compose up -d --build
docker exec ebpf_loader sh -c 'cd /opt/mission && make clean 2>/dev/null; make all'
```

No próprio host (opcional), se as ferramentas estiverem instaladas:

```bash
make
make -f Makefile.apps   # só as apps
```

## Execução (resumido)

1. `docker compose up -d` — sobe `mc_app_a`, `mc_app_b` e o `ebpf_loader` (este fica em `tail -f /dev/null` até você usar `docker exec`).

2. `docker exec ebpf_loader sh -c 'cd /opt/mission && make all'` — gera o skeleton e o binário `loader` (artefatos também aparecem no diretório do projeto no host).

3. Ponte Docker: `br-` + primeiros 12 caracteres hex do ID da rede `mission_control_net` (o loader com `network_mode: host` enxerga essa interface no kernel do host).

4. `docker exec ebpf_loader sh -c 'cd /opt/mission && ./loader br-<id>'` — roda como root no container privilegiado; não precisa de `sudo` no host. O `loader.c` continua ajustando `RLIMIT_MEMLOCK`.

5. O notebook `mission_control_lab.ipynb` segue esses passos. O loader imprime a linha do enunciado quando o ring buffer recebe o evento de *deadlock*.

## Notas e limitações

- O mapeamento “impasse **sem** payload após a conexão estabilizada” e o *timeout* de 5 segundos são aproximados: o estado no eBPF usa contagem de segmentos no par de IPs, não uma FSM completa por 4-tupla.

- A injeção de RST vale para o **segmento que o TC está processando**; é preciso tráfego (aqui, keepalives) para, depois do intervalo, a lógica disparar.

- No **WSL2**, Docker e a ponte podem se comportar de forma diferente de um Linux nativo; a interface *br-* que o eBPF enxerga no host tem que ser a certa.

- **Permissões**: com o fluxo `ebpf_loader` (`privileged: true`, `pid: host`, `network_mode: host`), o `make` e o `./loader` rodam como root dentro do container, no **mesmo kernel** do host — não é preciso `sudo` no host para o loader. Se você compilar e rodar o loader direto no host, aí sim costuma precisar de privilégios elevados e `RLIMIT_MEMLOCK`.

## Licenças e cabeçalhos

- O programa *kernel* (`deadlock_bpf.c`) declara `GPL-2.0` na seção *license* SEC, o que costuma ser exigido nesse contexto.
- *Loader* e aplicações usam cabeçalhos de licença leves; confira no próprio arquivo se a instituição pede algo específico.

## Referências úteis

- [libbpf](https://github.com/libbpf/libbpf) e os exemplos oficiais (*libbpf-bootstrap*).
- Documentação do *bpftool* para `btf dump` e `gen skeleton`.
- *Man pages* / documentação de `bpf(2)` e *TC BPF* (clsact, ingress/egress).

Se você for replicar o laboratório, vale anotar versão de kernel, libbpf e o comando de pacote (`apt`, `dnf`, etc.) da máquina, para o próximo semestre não ter surpresa.
