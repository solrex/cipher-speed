package com.yangwenbo.cipherspeed;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

/**
 * Created by Wenbo Yang on 2017/11/16.
 */

public class CipherBenchmark {
    private static String TAG = "CipherBenchmark";
    private Handler _ouput_handle;

    CipherBenchmark(Handler hd) {
        _ouput_handle = hd;
    }

    void print(String log) {
        Log.i(TAG, log);
        Message msg = _ouput_handle.obtainMessage();
        msg.obj = log + "\n";
        _ouput_handle.sendMessage(msg);
    }

    public byte[] random_bytes(int len) {
        Random random = new Random();
        byte[] bytes = new byte[len];
        random.nextBytes(bytes);
        return bytes;
    }

    public void runtest() {
        try {
            SecretKey aes_key_128 = new SecretKeySpec(random_bytes(16), "AES");
            SecretKey aes_key_256 = new SecretKeySpec(random_bytes(32), "AES_256");
            SecretKey des_key = new SecretKeySpec(random_bytes(8), "DES");
            SecretKey desede_key = new SecretKeySpec(random_bytes(16), "DESede");
            byte[] tea_key = random_bytes(16);
            IvParameterSpec aes_iv = new IvParameterSpec(random_bytes(16));
            IvParameterSpec des_iv = new IvParameterSpec(random_bytes(8));
            byte[] plain = random_bytes(10*1024*1024);
            byte[] cipher_data, dec_plain;
            //byte[] plain = "Test Cipher".getBytes();

            long start_time = 0;
            long end_time = 0;
            double time_diff = 0;
            String transfomation = "";
            Cipher cipher;

            print("# AES: ");
            transfomation = "AES/CBC/PKCS5Padding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, aes_key_128, aes_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, aes_key_128, aes_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "AES/CBC/NoPadding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, aes_key_128, aes_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, aes_key_128, aes_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "AES/ECB/PKCS5Padding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, aes_key_128);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, aes_key_128);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "AES/ECB/NoPadding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, aes_key_128);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, aes_key_128);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "AES/GCM/NOPADDING";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, aes_key_128, aes_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, aes_key_128, aes_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            print("# DES: ");
            // DES Require IV 8 bytes long
            transfomation = "DES/CBC/PKCS5Padding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, des_key, des_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, des_key, des_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "DES/CBC/NoPadding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, des_key, des_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, des_key, des_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "DES/ECB/PKCS5Padding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, des_key);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, des_key);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "DES/ECB/NoPadding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, des_key);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, des_key);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            print("# 3DES: ");
            transfomation = "DESede/CBC/PKCS5Padding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, desede_key, des_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, desede_key, des_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "DESede/CBC/NoPadding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, desede_key, des_iv);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, desede_key, des_iv);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "DESede/ECB/PKCS5Padding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, desede_key);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, desede_key);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            transfomation = "DESede/ECB/NoPadding";
            cipher = Cipher.getInstance(transfomation);
            cipher.init(Cipher.ENCRYPT_MODE, desede_key);
            start_time = System.nanoTime();
            cipher_data = cipher.doFinal(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            cipher.init(Cipher.DECRYPT_MODE, desede_key);
            start_time = System.nanoTime();
            dec_plain = cipher.doFinal(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }

            print("# TEA: ");
            transfomation = "TEA";
            TEA tea = new TEA(tea_key);
            start_time = System.nanoTime();
            cipher_data = tea.encrypt(plain);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            print("* [" + transfomation + "] ENC: " + String.format("%.1f", plain.length/time_diff/1024) + " KB/ms");
            start_time = System.nanoTime();
            dec_plain = tea.decrypt(cipher_data);
            end_time = System.nanoTime();
            time_diff = (end_time - start_time)/1e6;
            if (!Arrays.equals(dec_plain, plain)) {
                print(transfomation + " DECRYPT FAILED");
            } else {
                print("* [" + transfomation + "] DEC: " + String.format("%.1f", cipher_data.length/time_diff/1024) + " KB/ms");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}