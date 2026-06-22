package com.github.telarand.ws_android.bridge;

import com.github.telarand.ws_android.crypto.AesCtr;

/**
 * Контейнер для четырёх AES-CTR шифровальщиков.
 */
public final class CryptoCtx {
    public final AesCtr.Encryptor cltDec;
    public final AesCtr.Encryptor cltEnc;
    public final AesCtr.Encryptor tgEnc;
    public final AesCtr.Encryptor tgDec;

    public CryptoCtx(AesCtr.Encryptor cltDec,
                     AesCtr.Encryptor cltEnc,
                     AesCtr.Encryptor tgEnc,
                     AesCtr.Encryptor tgDec) {
        this.cltDec = cltDec;
        this.cltEnc = cltEnc;
        this.tgEnc = tgEnc;
        this.tgDec = tgDec;
    }
}