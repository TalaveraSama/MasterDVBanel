/*
 * tbs_newcamd.h - Criptografia del protocolo Newcamd (port de OSCam).
 *
 * Ver tbs_newcamd.c para la explicacion completa. Licencia: GPLv3.
 */

#ifndef TBS_NEWCAMD_H
#define TBS_NEWCAMD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Deriva la clave de sesion de 16 bytes.
 *   key1 = 14 bytes de clave inicial del servidor
 *   key2 = deskey del usuario (14 bytes), len = 14
 *   des16 = salida de 16 bytes
 * Devuelve 0 si todo va bien, -1 con argumentos invalidos. */
int nc_login_key_get(const uint8_t *key1, const uint8_t *key2, int len, uint8_t *des16);

/* Cifra una trama completa con dos bytes iniciales reservados para longitud;
 * `buffer` necesita len + 16 bytes. Devuelve la longitud total de la trama
 * (incluidos esos dos bytes, padding, checksum e IV) o -1. El caller escribe la
 * longitud TCP en buffer[0..1] tras cifrar. */
int nc_encrypt(uint8_t *buffer, int len, const uint8_t *deskey);

/* Descifra la trama completa (incluyendo longitud TCP) y valida el checksum.
 * Devuelve la longitud útil sin IV, todavía con la cabecera de 2 bytes, o -1. */
int nc_decrypt(uint8_t *buffer, int len, const uint8_t *deskey);

#ifdef __cplusplus
}
#endif

#endif /* TBS_NEWCAMD_H */
