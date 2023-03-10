package com.example.demo.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.example.demo.exceptions.SpringRedditException;
import com.example.demo.model.User;

import io.jsonwebtoken.Jwts;

@Service
public class JwtProvider {
	
	private KeyStore keyStore;
	
	
	public void init() {
		try {
			keyStore=KeyStore.getInstance("JKS");
			InputStream resourceAsStream=getClass().getResourceAsStream("/springblog.jks");
			keyStore.load(resourceAsStream,"secret".toCharArray());
		}catch(KeyStoreException|CertificateException|NoSuchAlgorithmException|IOException e) {
			throw new SpringRedditException("Exception occurred while loading keystore");
		}
	}
	
	public String generateToken(Authentication authentication) {
		User principal = (User) authentication.getPrincipal();
		return Jwts.builder()
				.setSubject(principal.getUsername())
				.signWith(getPrivateKey())
				.compact();
	}

	private Key getPrivateKey() {
		try {
		return (PrivateKey) keyStore.getKey("springblog","secret".toCharArray());		
		}catch (KeyStoreException|NoSuchAlgorithmException|UnrecoverableKeyException e) {
			throw new SpringRedditException("Exception occurred while retrieving public key from keystore");
		}
	}
}
