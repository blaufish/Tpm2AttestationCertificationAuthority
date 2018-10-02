package com.github.crocs.muni.roca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class BrokenKeyTest {
	// https://github.com/crocs-muni/roca/blob/master/roca/tests/data/cert01.pem
	private static final String CERT01_PEM_NEGATIVE = "MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\n"
			+ "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
			+ "DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\n"
			+ "SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\n"
			+ "GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
			+ "AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\n"
			+ "q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\n"
			+ "SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\n"
			+ "Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\n"
			+ "a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n"
			+ "/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\n"
			+ "AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\n"
			+ "CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\n"
			+ "bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\n"
			+ "c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\n"
			+ "VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\n"
			+ "ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\n"
			+ "MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\n"
			+ "Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\n"
			+ "AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\n"
			+ "uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\n"
			+ "wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\n"
			+ "X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\n"
			+ "PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\n" + "KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==";
	// https://github.com/crocs-muni/roca/blob/master/roca/tests/data/cert04.pem
	private static final String CERT04_PEM_POSITIVE = "MIICpTCCAYwCCQC2u0PIfFaGMjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
			+ "b2NhbGhvc3QwHhcNMTcxMDE2MTkzODIxWhcNMTgxMDE2MTkzODIxWjAUMRIwEAYD\n"
			+ "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQJZ\n"
			+ "J7UrpeaMjJJou5IY83ZzYUymVBj0dFsUPNTuU/lJHJoOHC8jqVFjBq/784ZnuHG8\n"
			+ "DMguYPW7Gp+hWlZxp2XJ8huVh9gBFZZDcqODyIOw3L9sd1cGsx6v8+P9SIVZoIze\n"
			+ "og+al8TFm2uKjuykV9SoINSVCfdZM2MCvKGjaQsICRgR+Fjy6M6lpiNVrW4EHRk1\n"
			+ "7aWSibWXaDtz4mV650v/x2Dk1RPMh9uTVZGOqgjTmLvl9oNdyHElIRubNrOgvHC5\n"
			+ "k6bLP30stAYd5z25cslCrfmVW2/kzZDwDQiK7ASvH17/kfIa9e1EYXx9uAk/lTZt\n"
			+ "smWAxK85neuU+bFBMFvhAgMBAAEwDQYJKoZIhvcNAQELBQADggECAAG7W49CYRUk\n"
			+ "YAFRGXu3M85MKOISyc/kkJ8nbHdV6GxJ05FkoDKbcbZ7nncJiIp2VMAMEIP4bRTJ\n"
			+ "5U4g4vSZlmCs8BDmV3Ts/tbDCM6eqK+2hwjhUnCnmmsLt4xVUeAAsWUHl9AVtjzd\n"
			+ "oYlm1Kk20QBzNpsvM/gFS5B+duHvTSfELfoq9Pdfvmn2gEXJHe9scO8bfT3fm15z\n"
			+ "R6AUYsSsxAhup2Rix6jgJ14KGsh6uVm6jhz9aBTBcgx7iMuuP8zUbUE6nryHYXnR\n"
			+ "cSvuYSesTCoFfnL7elrZDak/n0jLfwUD80aWnReJfu9QQGdqdDnSG8lSQ1XPOC7O\n" + "/hFW9l0TCzOE";

	@Test
	void selfIsOK() {
		RSAPublicKey pubkey = keyGen();
		assertFalse(BrokenKey.isAffected(pubkey));

	}

	@Test
	void testIsAffectedX509Certificate() {
		assertFalse(BrokenKey.isAffected(certFromString(CERT01_PEM_NEGATIVE)));
		assertTrue(BrokenKey.isAffected(certFromString(CERT04_PEM_POSITIVE)));
	}

	@Test
	void testIsAffectedRSAPublicKey() {
		assertFalse(BrokenKey.isAffected((RSAPublicKey) certFromString(CERT01_PEM_NEGATIVE).getPublicKey()));
		assertTrue(BrokenKey.isAffected((RSAPublicKey) certFromString(CERT04_PEM_POSITIVE).getPublicKey()));
	}

	private RSAPublicKey keyGen() {
		RSAPublicKey publicKey;

		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		keyGen.initialize(2048);
		publicKey = (RSAPublicKey) keyGen.genKeyPair().getPublic();
		return publicKey;
	}

	private X509Certificate certFromString(String base64) {

		byte[] bytes = Base64.getDecoder().decode(base64.replace("\n", ""));
		Certificate cert;
		CertificateFactory certFactory;
		try {
			certFactory = CertificateFactory.getInstance("X.509");
			cert = certFactory.generateCertificate(new ByteArrayInputStream(bytes));
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
		return (X509Certificate) cert;
	}
}
