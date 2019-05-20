#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h>
#include <gmp.h>

#include "consts.h"

#define DEBUG 0

#define CMD_SIZE 256
#define X_BUF_SIZE 100
#define NONCE_SIZE 20

#define MAX_SIGNS_NUM 2


char gCmd[CMD_SIZE];
char xs[X_BUF_SIZE]; // read from file


typedef struct _ctx_t {
  // DSA
  mpz_t x; // dsa secret
  mpz_t y;
  mpz_t p;
  mpz_t q;
  mpz_t g;

  // constants
  mpz_t A;
  mpz_t Abar;
  mpz_t MA;
  mpz_t B;
  mpz_t Bbar;
  mpz_t MB;
  mpz_t KA;
  mpz_t KB;
  mpz_t Kbar;
  mpz_t MK;

  // internal state
  mpz_t stA;
  mpz_t stB;

  // additional state
  unsigned int signsNum;
  mpz_t lastM;
} ctx_t;


void init_ctx(ctx_t* ctx);

void handle_main_loop();
void handle_sign();
void handle_execute();

void do_sign(ctx_t* ctx, unsigned char* data, size_t len);
void sign(ctx_t* ctx, mpz_t* _r, mpz_t* _s, unsigned char* data, size_t len);
void get_next_nonce(ctx_t* ctx, mpz_t* _k);
int verify(ctx_t* ctx, unsigned char* data, size_t len, mpz_t r, mpz_t s);
void sha1(mpz_t* hm, unsigned char* data, size_t len);
void hexdump(char* hex, unsigned char* data, size_t len);
int get_string(char *buffer, unsigned int len);
char get_char();
void read_random_bytes(unsigned char *data, size_t bytes_num);
void get_random_mpz(mpz_t *out, unsigned int bytes_num);


int main() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    ctx_t* ctx = (ctx_t *) malloc(sizeof(ctx_t));
    init_ctx(ctx);

#if DEBUG
    gmp_printf("x: %Zd\n", ctx->x);
    gmp_printf("y: %Zd\n", ctx->y);
    gmp_printf("g: %Zd\n", ctx->g);
    gmp_printf("p: %Zd\n", ctx->p);
    gmp_printf("q: %Zd\n", ctx->q);
    gmp_printf("A: %Zd\n", ctx->A);
    gmp_printf("Abar: %Zd\n", ctx->Abar);
    gmp_printf("MA: %Zd\n", ctx->MA);
    gmp_printf("B: %Zd\n", ctx->B);
    gmp_printf("Bbar: %Zd\n", ctx->Bbar);
    gmp_printf("MB: %Zd\n", ctx->MB);
    gmp_printf("KA: %Zd\n", ctx->KA);
    gmp_printf("KB: %Zd\n", ctx->KB);
    gmp_printf("Kbar: %Zd\n", ctx->Kbar);
    gmp_printf("MK: %Zd\n", ctx->MK);
#endif

    handle_main_loop(ctx);
    return 0;
}


void init_ctx(ctx_t* ctx) {
    mpz_init(ctx->x);
    mpz_init(ctx->y);
    mpz_init(ctx->g);
    mpz_init(ctx->p);
    mpz_init(ctx->q);
    mpz_init(ctx->A);
    mpz_init(ctx->Abar);
    mpz_init(ctx->MA);
    mpz_init(ctx->B);
    mpz_init(ctx->Bbar);
    mpz_init(ctx->MB);
    mpz_init(ctx->KA);
    mpz_init(ctx->KB);
    mpz_init(ctx->Kbar);
    mpz_init(ctx->MK);
    mpz_init(ctx->stA);
    mpz_init(ctx->stB);
    mpz_init(ctx->lastM);

    FILE *f = fopen("privkey", "r");
    if (f == NULL) {
        printf("privkey not found. Contact the admins.\n");
        exit(1);
    }
    fgets(xs, X_BUF_SIZE, f);
    fclose(f);

    int err;
    err = mpz_set_str(ctx->x, xs, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->y, Y_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->g, G_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->p, P_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->q, Q_CONST, 10);
    assert (err == 0);

    err = mpz_set_str(ctx->A, A_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->Abar, ABAR_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->MA, MA_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->B, B_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->Bbar, BBAR_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->MB, MB_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->KA, KA_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->KB, KB_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->Kbar, KBAR_CONST, 10);
    assert (err == 0);
    err = mpz_set_str(ctx->MK, MK_CONST, 10);
    assert (err == 0);

    get_random_mpz(&(ctx->stA), 160/8);
    get_random_mpz(&(ctx->stB), 160/8);

    ctx->signsNum = 0;
    mpz_set_ui(ctx->lastM, 0);
}


void handle_main_loop(ctx_t* ctx) {

    char choice = 0;
    while(choice != 'E') {

        printf("(S) sign\n");
        printf("(X) execute\n");
        printf("(E) exit\n");
        printf("> ");

        choice = get_char();
        switch (choice) {
            case 'S':
            case 's':
                handle_sign(ctx);
                break;
            case 'X':
            case 'x':
                handle_execute(ctx);
                break;
            case 'E':
            case 'e':
                break;
            default: {
                // printf("'%c' is not an official command\n", choice);
                break;
            }
        }
    }
}


void handle_sign(ctx_t* ctx) {
    printf("cmd:");

    int cmdLen = get_string(gCmd, CMD_SIZE);

    if (strcmp(gCmd, "the rules are the rules, no complaints") == 0) {
        do_sign(ctx, (unsigned char *) "the rules are the rules, no complaints", cmdLen);
    } else if (strcmp(gCmd, "reyammer can change the rules") == 0) {
        do_sign(ctx, (unsigned char *) "reyammer can change the rules", cmdLen);
    } else {
        printf("I don't like this rule.\n");
    }
}


void handle_execute(ctx_t* ctx) {
    char rStr[128];
    char sStr[128];
    printf("cmd:");
    int cmdLen = get_string(gCmd, CMD_SIZE);
    printf("r:");
    get_string(rStr, 60);
    printf("s:");
    get_string(sStr, 60);

    mpz_t r, s;
    mpz_init(r);
    mpz_init(s);
    mpz_set_str(r, rStr, 10);
    mpz_set_str(s, sStr, 10);

    if (verify(ctx, (unsigned char *) gCmd, cmdLen, r, s)) {
        system(gCmd);
    } else {
        printf("was that a valid rule? debatable.\n");
    }
}


void do_sign(ctx_t* ctx, unsigned char* data, size_t len) {
    mpz_t r, s;
    mpz_init(r);
    mpz_init(s);

    if (ctx->signsNum >= MAX_SIGNS_NUM) {
        printf("enough!\n");
        exit(1);
    }

    ctx->signsNum += 1;

    sign(ctx, &r, &s, data, len);
    gmp_printf("r: %Zd\n", r);
    gmp_printf("s: %Zd\n", s);
}


void sign(ctx_t* ctx, mpz_t* _r, mpz_t* _s, unsigned char* data, size_t len) {
    mpz_t r, s, k; // final values
    mpz_t kinv, hm, xr; // partial values
    mpz_init(r);
    mpz_init(s);
    mpz_init(k);
    mpz_init(kinv);
    mpz_init(hm);
    mpz_init(xr);

    sha1(&hm, data, len);

    if (mpz_cmp(hm, ctx->lastM) == 0) {
        printf("I have already signed this. Come on. :|\n");
        exit(1);
    }
    mpz_set(ctx->lastM, hm);

#if DEBUG
    gmp_printf("m: %Zd\n", hm);
    gmp_printf("stA (before): %Zd\n", ctx->stA);
    gmp_printf("stB (before): %Zd\n", ctx->stB);
#endif
    get_next_nonce(ctx, &k);
#if DEBUG
    gmp_printf("k: %Zd\n", k);
    gmp_printf("stA (after): %Zd\n", ctx->stA);
    gmp_printf("stB (after): %Zd\n", ctx->stB);
#endif

    // r
    mpz_powm(r, ctx->g, k, ctx->p);
    mpz_mod(r, r, ctx->q);

    // s
    mpz_invert(kinv, k, ctx->q);
    mpz_mul(xr, ctx->x, r);

    mpz_add(s, hm, xr);
    mpz_mul(s, kinv, s);
    mpz_mod(s, s, ctx->q);

    mpz_set(*_r, r);
    mpz_set(*_s, s);

    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(k);
    mpz_clear(kinv);
    mpz_clear(hm);
    mpz_clear(xr);
}


void get_next_nonce(ctx_t* ctx, mpz_t* _k) {
    // next nonce is put in _k
    
    mpz_t k, acc1, acc2;
    mpz_init(k);
    mpz_init(acc1);
    mpz_init(acc2);

    mpz_mul(acc1, ctx->KA, ctx->stA);
    mpz_mul(acc2, ctx->KB, ctx->stB);
    mpz_add(k, acc1, acc2);
    mpz_add(k, k, ctx->Kbar);
    mpz_mod(k, k, ctx->MK);

    mpz_mul(ctx->stA, ctx->A, k);
    mpz_add(ctx->stA, ctx->stA, ctx->Abar);
    mpz_mod(ctx->stA, ctx->stA, ctx->MA);

    mpz_mul(ctx->stB, ctx->B, k);
    mpz_add(ctx->stB, ctx->stB, ctx->Bbar);
    mpz_mod(ctx->stB, ctx->stB, ctx->MB);

    mpz_set(*_k, k);

    mpz_clear(k);
    mpz_clear(acc1);
    mpz_clear(acc2);
}


int verify(ctx_t* ctx, unsigned char* data, size_t len, mpz_t r, mpz_t s) {

    // check that r and s are in the corret range
    if (mpz_sgn(r) <= 0 || mpz_cmp(r, ctx->q) >= 0) {
        return 0;
    }

    if (mpz_sgn(s) <= 0 || mpz_cmp(s, ctx->q) >= 0) {
        return 0;
    }

    mpz_t v, w, hm, u1, u2, e1, e2;
    mpz_init(v);
    mpz_init(w);
    mpz_init(hm);
    mpz_init(u1);
    mpz_init(u2);
    mpz_init(e1);
    mpz_init(e2);

    mpz_invert(w, s, ctx->q);
    sha1(&hm, data, len);
    // u1
    mpz_mul(u1, hm, w);
    mpz_mod(u1, u1, ctx->q);
    // u2
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, ctx->q);
    // e1, e2
    mpz_powm(e1, ctx->g, u1, ctx->p);
    mpz_powm(e2, ctx->y, u2, ctx->p);
    // v
    mpz_mul(v, e1, e2);
    mpz_mod(v, v, ctx->p);
    mpz_mod(v, v, ctx->q);

    if (mpz_cmp(v, r) == 0) {
        printf("OK\n");
        return 1;
    } else {
        return 0;
    }
}


void sha1(mpz_t* hm, unsigned char* data, size_t len) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    char hexdigest[2*SHA_DIGEST_LENGTH+1];
    SHA1(data, len, digest);
    hexdump(hexdigest, digest, SHA_DIGEST_LENGTH);
    mpz_set_str(*hm, hexdigest, 16);
}


void hexdump(char* hex, unsigned char* data, size_t len) {
    int i;
    for (i=0; i<len; i++) {
        sprintf(hex+2*i, "%02x", data[i]);
    }
}


int get_string(char *buffer, unsigned int len) {
    // Read a string from stdin until EOF or a \n.

    unsigned int i=0;
    size_t n;
    while (i<(len-1)) { // save space for \0
        n = fread(&buffer[i], 1, 1, stdin);
        if (n != 1) {
            // fread failed, let's err out
            fprintf(stderr, "fread fail\n");
            exit(1);
        }
        if (buffer[i] == '\n') {
            buffer[i] = '\0';
            // we are done
            return i;
        }
        i++;
    }
    assert (i < len);
    // no new line found, but we have read too much anyways
    buffer[i] = '\0';
    return i;
}


char get_char() {
    char choice[10];
    get_string(choice, 10);
    return choice[0];
}


void read_random_bytes(unsigned char *data, size_t bytes_num) {
    // assume data is already allocated, of size bytes_num bytes

    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        printf("Can't open /dev/urandom. Contact the admins.\n");
        exit(1);
    }

    unsigned int i=0;
    size_t n;
    while (i<bytes_num) { // save space for \0
        n = fread(&data[i], 1, 1, f);
        if (n != 1) {
            // fread failed, let's err out
            fprintf(stderr, "fread random fail\n");
            exit(1);
        }
        i++;
    }

    int ret = fclose(f);
    assert (ret == 0);
}

void get_random_mpz(mpz_t *out, unsigned int bytes_num) {
    unsigned char* data = (unsigned char *) malloc(bytes_num+1);
    char* hexdata = (char *) malloc(2*bytes_num+1);
    read_random_bytes(data, bytes_num);
    hexdump(hexdata, data, bytes_num);
    mpz_set_str(*out, hexdata, 16);
    free(data);
    free(hexdata);
}
