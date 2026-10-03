"""
analisis_tiempos.py - Evidencia para RS4 (mitigación de ataques de canal lateral de tiempo).

Compara cuánto tarda  `==`  y  `secrets.compare_digest`  según en qué posición
está el PRIMER byte distinto entre la firma correcta y la firma falsa:

  - `==` se detiene en el primer byte distinto: cuanto más tarde falle, más tarda.
  - `compare_digest` recorre siempre todo: el tiempo no depende de dónde falle.

Se miden dos casos:
  A) Tamaño real: 64 bytes (un HMAC-SHA256 en hexadecimal). La diferencia de `==`
     es de nanosegundos y puede quedar oculta por el ruido del ordenador.
  B) Ampliado: 1.000.000 de bytes. Mismo mecanismo, pero el efecto se ve con claridad.

Uso:
    python analisis_tiempos.py
Genera:  tiempos.csv  (siempre)  y  tiempos.png  (solo si está matplotlib instalado)

Consejo: cierra programas pesados mientras se ejecuta, para reducir el ruido.
"""
import csv
import random
import secrets
import statistics
import time
from pathlib import Path

SALIDA = Path(__file__).resolve().parent

COMPARADORES = {
    "==": lambda a, b: a == b,
    "compare_digest": secrets.compare_digest,
}

# (nombre, longitud en bytes, llamadas por muestra, rondas)
CASOS = [
    ("A_tamano_real_64B", 64, 20000, 150),
    ("B_ampliado_1MB", 1_000_000, 20, 100),
]


def ns_por_llamada(funcion, a, b, llamadas):
    t0 = time.perf_counter_ns()
    for _ in range(llamadas):
        funcion(a, b)
    return (time.perf_counter_ns() - t0) / llamadas


def medir_caso(longitud, llamadas, rondas):
    correcta = secrets.token_bytes(longitud)
    posiciones = [0, longitud // 4, longitud // 2, (3 * longitud) // 4, longitud - 1]

    # Una firma falsa por posición: igual que la correcta salvo UN byte.
    falsas = {}
    for p in posiciones:
        copia = bytearray(correcta)
        copia[p] ^= 0xFF
        falsas[p] = bytes(copia)

    muestras = {(nombre, p): [] for nombre in COMPARADORES for p in posiciones}

    # Se mezcla el orden en cada ronda para que la deriva del procesador
    # (turbo, temperatura...) no favorezca a ninguna posición.
    for _ in range(rondas):
        orden = posiciones[:]
        random.shuffle(orden)
        for p in orden:
            for nombre, funcion in COMPARADORES.items():
                muestras[(nombre, p)].append(
                    ns_por_llamada(funcion, correcta, falsas[p], llamadas)
                )
    return posiciones, muestras


def resumen(posiciones, muestras):
    filas = []
    for nombre in COMPARADORES:
        for p in posiciones:
            datos = muestras[(nombre, p)]
            q = statistics.quantiles(datos, n=4)
            filas.append({
                "comparador": nombre,
                "posicion_primer_byte_distinto": p,
                "mediana_ns": round(statistics.median(datos), 1),
                "q1_ns": round(q[0], 1),
                "q3_ns": round(q[2], 1),
            })
    return filas


def variacion(filas, nombre, posiciones):
    med = {f["posicion_primer_byte_distinto"]: f["mediana_ns"]
           for f in filas if f["comparador"] == nombre}
    primero, ultimo = med[posiciones[0]], med[posiciones[-1]]
    return (ultimo - primero) / primero * 100


def longitud_de(nombre_caso):
    return next(l for n, l, _, _ in CASOS if n == nombre_caso)


def main():
    todas = []
    graficas = {}
    for nombre_caso, longitud, llamadas, rondas in CASOS:
        print(f"\n=== Caso {nombre_caso}  ({longitud} bytes, {rondas} rondas) ===")
        posiciones, muestras = medir_caso(longitud, llamadas, rondas)
        filas = resumen(posiciones, muestras)
        graficas[nombre_caso] = (posiciones, filas)

        print(f"{'comparador':<16}{'1er byte distinto':>20}{'mediana (ns)':>16}{'Q1-Q3 (ns)':>24}")
        for f in filas:
            rango = f"{f['q1_ns']:.0f} - {f['q3_ns']:.0f}"
            print(f"{f['comparador']:<16}{f['posicion_primer_byte_distinto']:>20}"
                  f"{f['mediana_ns']:>16.1f}{rango:>24}")
            todas.append({"caso": nombre_caso, "longitud_bytes": longitud, **f})

        v_eq = variacion(filas, "==", posiciones)
        v_cd = variacion(filas, "compare_digest", posiciones)
        print("\nVariación entre fallar en el primer byte y en el último:")
        print(f"   ==              : {v_eq:+.1f} %   (x{1 + v_eq / 100:.2f})")
        print(f"   compare_digest  : {v_cd:+.1f} %   (x{1 + v_cd / 100:.2f})")

    with open(SALIDA / "tiempos.csv", "w", newline="", encoding="utf-8") as fh:
        escritor = csv.DictWriter(fh, fieldnames=list(todas[0].keys()))
        escritor.writeheader()
        escritor.writerows(todas)
    print(f"\nDatos guardados en {SALIDA / 'tiempos.csv'}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib no está instalado: no se genera tiempos.png "
              "(instálalo con: pip install matplotlib)")
        return

    figura, ejes = plt.subplots(1, len(graficas), figsize=(12, 4.5))
    for eje, (nombre_caso, (posiciones, filas)) in zip(ejes, graficas.items()):
        for nombre in COMPARADORES:
            y = [f["mediana_ns"] for f in filas if f["comparador"] == nombre]
            eje.plot(posiciones, y, marker="o", label=nombre)
        if longitud_de(nombre_caso) > 1000:
            eje.set_yscale("log")  # == y compare_digest difieren en órdenes de magnitud
        eje.set_title(nombre_caso)
        eje.set_xlabel("Posición del primer byte distinto")
        eje.set_ylabel("Tiempo por comparación (ns, mediana)")
        eje.grid(alpha=0.3)
        eje.legend()
    figura.tight_layout()
    figura.savefig(SALIDA / "tiempos.png", dpi=150)
    print(f"Gráfica guardada en {SALIDA / 'tiempos.png'}")


if __name__ == "__main__":
    main()
