/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.common.crypto;

import xyz.kyngs.librelogin.api.crypto.CryptoProvider;
import xyz.kyngs.librelogin.api.crypto.HashedPassword;
import xyz.kyngs.librelogin.common.util.CryptoUtil;

import javax.annotation.Nullable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha512CryptoProvider implements CryptoProvider {

    @Override
    @Nullable
    public HashedPassword createHash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hash = md.digest(password.getBytes());
            String hashString = CryptoUtil.bytesToHexString(hash);
            return new HashedPassword(hashString, null, "SHA-512");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    @Override
    public boolean matches(String input, HashedPassword password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] inputHash = md.digest(input.getBytes());
            String inputHashString = CryptoUtil.bytesToHexString(inputHash);
            return inputHashString.equals(password.hash());
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    @Override
    public String getIdentifier() {
        return "SHA-512";
    }

}
