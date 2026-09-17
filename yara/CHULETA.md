# Chuleta YARA

> **Ten este fichero abierto en una segunda ventana durante toda la clase.**
> Es lo que vas a mirar mientras haces los ejercicios.

## Anatomía de una regla

```yara
rule mal_ransomware_note_lockbit          // nombre: tipo _ familia _ detalle
{
    meta:                                 // para humanos, no afecta a la detección
        author      = "tu nombre"
        description = "qué detecta"
        date        = "2026-09-08"
        hash        = "sha256 de una muestra que sí detecta"
        reference   = "url del informe o del blog"

    strings:                              // QUÉ buscar
        $a = "Use TOR Browser:" fullword ascii    // texto
        $b = { 4D 5A 90 00 }                      // bytes en hexadecimal
        $c = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/    // expresión regular

    condition:                            // CUÁNDO doy positivo
        uint16(0) == 0x5A4D and filesize < 200KB and 2 of them
}
```

## Modificadores de string

| Modificador | Qué hace |
|---|---|
| `nocase` | Da igual mayúsculas o minúsculas |
| `wide` | Dos bytes por carácter (`B\x00o\x00r\x00…`), típico en binarios de Windows |
| `ascii` | Un byte por carácter (por defecto). Se puede combinar: `wide ascii` |
| `fullword` | Palabra entera: no hace match dentro de otra palabra más larga |
| `base64` | Busca también la versión codificada en base64 de la string |

## Condiciones

| Expresión | Significado |
|---|---|
| `any of them` | Basta una string. **Cuidado: mucho ruido.** |
| `all of them` | Todas. Suele dar cero detecciones. |
| `2 of them` | Dos indicios independientes. **El punto medio que casi siempre quieres.** |
| `1 of ($a*)` | Cualquier string cuyo nombre empiece por `$a` |
| `#a >= 3` | La string `$a` aparece al menos 3 veces |
| `$a at 0` | La string `$a` está justo al principio del fichero |
| `$a in (0..1024)` | La string `$a` está en los primeros 1024 bytes |
| `filesize < 100KB` | El fichero pesa menos de 100 KB |
| `and` `or` `not` | Los operadores lógicos de siempre |

## Magic numbers más usados

| Formato | Condición |
|---|---|
| PE (`.exe`, `.dll`) | `uint16(0) == 0x5A4D` |
| ELF (Linux) | `uint16(0) == 0x457F` |
| PDF | `uint32(0) == 0x25504446` |
| ZIP / docx / xlsx | `uint32(0) == 0x04034B50` |
| RTF | `uint32(0) == 0x74725C7B` |
| doc / ppt / xls (antiguos) | `uint32be(0) == 0xD0CF11E0` |

> **¿Por qué `0x5A4D` y no `0x4D5A`?** Porque x86 es *little endian*: los bytes `4D 5A`
> se leen en memoria en orden inverso. Escribes el valor tal y como la máquina lo lee.

## Comandos

```bash
yara64.exe -s   regla.yara fichero.exe      # enseña qué string ha hecho match
yara64.exe -r   regla.yara carpeta\         # recursivo, entra en subcarpetas
yara64.exe -c   regla.yara carpeta\         # solo cuenta los positivos
yara64.exe -n   regla.yara carpeta\         # al revés: lo que NO cumple la regla
strings -n 10 fichero.exe                   # saca las strings del binario
```

## Las tres reglas de oro

1. **Una string demasiado común = falso positivo.** Si aparece en un email normal (por ejemplo), no sirve.
2. **Una string demasiado concreta = falso negativo.** La siguiente versión del malware ya no cae.
3. **Prueba siempre contra ficheros legítimos antes de desplegar.** Es lo que separa una regla
   que se despliega de una que te devuelven al día siguiente con 4.000 alertas.
