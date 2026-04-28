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
| `docker-compose.yml` + `Dockerfile` | Dois containers com IPs fixos na faixa 172.28.0.0/16, rede *bridge* dedicada, sem simulação falsa de rede. |
| `mission_control_lab.ipynb` | Células *shell* para compilar, subir os containers, rodar o loader e inspecionar logs. |

O Makefile do host organiza isso: gera `vmlinux.h` a partir de `/sys/kernel/btf/vmlinux`, compila `deadlock_bpf.c` → `deadlock_bpf.o` com `clang` (*target bpf*), e roda `bpftool gen skeleton` para o `.skel.h`. Na **linkagem** do *loader* entram ainda **libelf** e **zlib** (além do que o `pkg-config` da libbpf trouxer).

## Dependências (máquina host Linux)

- **Kernel** com BTF acessível (`/sys/kernel/btf/vmlinux` é o padrão no `Makefile`). Sem BTF não dá para seguir o fluxo *vmlinux.h* + skeleton do jeito que o repo está hoje.
- **clang** e **LLVM** (*toolchain* com *target* `bpf`).
- **bpftool** (às vezes no pacote `linux-tools` ou equivalente).
- **libbpf** em versão de desenvolvimento, com arquivos de cabeçalho e `.pc` para `pkg-config` (em muitas distros: `libbpf-dev`).
- **elfutils** (libelf) e **zlib** (link `-lelf -lz`, como no `Makefile` após o `pkg-config` da libbpf).
- **GNU make**, **gcc** (apps e *loader*).
- **Docker** e **docker compose** para a parte dos containers.

Dentro dos containers basta a imagem base (Debian no `Dockerfile`) com `gcc` e *glibc* para as duas aplicações.

## Compilação

```bash
make         # vmlinux.h, deadlock_bpf.o, skeleton, binário loader, app_a e app_b
# ou só as apps
make -f Makefile.apps
```

Imagem Docker (só com as *apps*):

```bash
docker compose build
```

## Execução (resumido)

1. Subir os serviços: `docker compose up -d` (a partir do diretório com `docker-compose.yml`).

2. Identificar a ponte (ex.: `br-` + primeiros 12 hex do ID da rede) ou deixar o `loader` tentar uma interface `br-*` cujo endereço caia em 172.28.0.0/16.

3. O *loader* precisa de **privilégios elevados** (e, em muitas máquinas, limite de memória bloqueada; o `loader.c` ajusta `RLIMIT_MEMLOCK` para o máximo, como em vários exemplos de libbpf).

4. O notebook `mission_control_lab.ipynb` acompanha esses passos; o ideal é abri-lo com o diretório de trabalho na pasta do projeto (onde estão o `Makefile` e o `docker-compose.yml`).

5. O loader imprime a linha pedida no enunciado quando o ring buffer recebe o evento de *deadlock*.

## Notas e limitações

- O mapeamento “impasse **sem** payload após a conexão estabilizada” e o *timeout* de 5 segundos são aproximados: o estado no eBPF usa contagem de segmentos no par de IPs, não uma FSM completa por 4-tupla.

- A injeção de RST vale para o **segmento que o TC está processando**; é preciso tráfego (aqui, keepalives) para, depois do intervalo, a lógica disparar.

- No **WSL2**, Docker e a ponte podem se comportar de forma diferente de um Linux nativo; a interface *br-* que o eBPF enxerga no host tem que ser a certa.

- **Permissões**: carregar eBPF, criar o *qdisc* TC e o anexo `bpf_tc_*` exige *capabilities* adequadas com `sudo` — ou o modo *rootless* configurado, o que a maioria dos cursos não cobre.

## Licenças e cabeçalhos

- O programa *kernel* (`deadlock_bpf.c`) declara `GPL-2.0` na seção *license* SEC, o que costuma ser exigido nesse contexto.
- *Loader* e aplicações usam cabeçalhos de licença leves; confira no próprio arquivo se a instituição pede algo específico.

## Referências úteis

- [libbpf](https://github.com/libbpf/libbpf) e os exemplos oficiais (*libbpf-bootstrap*).
- Documentação do *bpftool* para `btf dump` e `gen skeleton`.
- *Man pages* / documentação de `bpf(2)` e *TC BPF* (clsact, ingress/egress).

Se você for replicar o laboratório, vale anotar versão de kernel, libbpf e o comando de pacote (`apt`, `dnf`, etc.) da máquina, para o próximo semestre não ter surpresa.
