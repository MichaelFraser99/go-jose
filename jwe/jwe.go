package jwe

/*
   BASE64URL(UTF8(JWE Protected Header)) || '.' ||
   BASE64URL(JWE Encrypted Key) || '.' ||
   BASE64URL(JWE Initialization Vector) || '.' ||
   BASE64URL(JWE Ciphertext) || '.' ||
   BASE64URL(JWE Authentication Tag)
*/
//todo: unfinished - do not use

// VerifyCompactSerialization - unfinished - do not use
//func VerifyCompactSerialization(compactSerialization string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (protectedHeader, body map[string]any, err error) {
//	components := strings.Split(compactSerialization, ".")
//	if len(components) != 5 {
//		return nil, nil, fmt.Errorf("%winvalid compact serialization format", joseerror.MalformedToken)
//	}
//
//	protectedHeader, err = jsonutils.DecodeBase64urlMap(components[0])
//	if err != nil {
//		return nil, nil, fmt.Errorf("%werror decoding protected header: %v", joseerror.MalformedToken, err)
//	}
//	_, err = base64.RawURLEncoding.DecodeString(components[1])
//	if err != nil {
//		return nil, nil, fmt.Errorf("%werror decoding encrypted key: %v", joseerror.MalformedToken, err)
//	}
//	_, err = base64.RawURLEncoding.DecodeString(components[2])
//	if err != nil {
//		return nil, nil, fmt.Errorf("%werror decoding initialization vector: %v", joseerror.MalformedToken, err)
//	}
//	_, err = base64.RawURLEncoding.DecodeString(components[3])
//	if err != nil {
//		return nil, nil, fmt.Errorf("%werror decoding ciphertext: %v", joseerror.MalformedToken, err)
//	}
//	_, err = base64.RawURLEncoding.DecodeString(components[4])
//	if err != nil {
//		return nil, nil, fmt.Errorf("%werror decoding authentication tag: %v", joseerror.MalformedToken, err)
//	}
//
//	var jwkRetrievers []model.Retriever
//
//	if outOfBoundsPublicKey != nil {
//		jwkRetrievers = append(jwkRetrievers, outOfBoundsPublicKey)
//	}
//
//	headerJwkRetrievers, err := header.ValidateHeader(protectedHeader, nil, model.JWE) //todo: sort out client providing
//	if err != nil {
//		return nil, nil, fmt.Errorf("%werror validating header: %v", joseerror.MalformedToken, err)
//	}
//
//	jwkRetrievers = append(jwkRetrievers, headerJwkRetrievers...)
//
//	if len(jwkRetrievers) == 0 {
//		return nil, nil, fmt.Errorf("%wno cyptographic material provided for decryption", joseerror.MalformedToken)
//	}
//
//	algorithm := jwa.GetAlgorithm(protectedHeader["alg"].(string)) //validated to exist and be of correct type earlier
//
//	if opts != nil && len(opts.AllowedSigningAlgorithms) > 0 { //todo: this doesn't make sense for jwe
//		if !slices.Contains(opts.AllowedSigningAlgorithms, algorithm) {
//			return nil, nil, fmt.Errorf("%walgorithm not permitted by application-level constraints", joseerror.DecryptionFailed)
//		}
//	}
//
//	var noKeyIdentifierErrors []error
//	for _, retriever := range jwkRetrievers {
//		var publicKeys []crypto.PublicKey
//		publicKeys, err = retriever()
//		if err != nil {
//			if !errors.Is(err, joseerror.NoKeyIdentifierMatch) {
//				return nil, nil, err
//			} else {
//				//if error is 'no key identifier', we ignore failure and store for later reporting
//				noKeyIdentifierErrors = append(noKeyIdentifierErrors, err)
//				continue
//			}
//		}
//
//		for _, pubKey := range publicKeys {
//			validator, err := jws.GetValidator(algorithm, pubKey)
//			if err != nil {
//				continue //ignore public key invalid for given algorithm
//			}
//
//			valid, err := validator.ValidateSignature([]byte(fmt.Sprintf("%s.%s", components[0], components[1])), signature)
//			if err != nil {
//				continue //ignore errors on validating signatures
//			}
//
//			if valid {
//				return protectedHeader, body, nil
//			}
//		}
//	}
//
//	if len(noKeyIdentifierErrors) > 0 {
//		return nil, nil, fmt.Errorf("%wunable to validate jws signature - possibly due to the following errors encountered retrieving cryptographic material: %v", joseerror.DecryptionFailed, noKeyIdentifierErrors)
//	}
//
//	return nil, nil, fmt.Errorf("%wunable to decrypt jwe", joseerror.DecryptionFailed)
//}
