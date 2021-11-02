#Include "Protheus.ch"

/*/{Protheus.doc} Jwt
  
  JsonWebToken for Protheus using ADVPL

  @author Lucas Fidélis
  @since 02/11/2021
  @version P12
/*/
Class Jwt

  Data cSecret

  Method New() Constructor
  Method Sign()
  Method Verify()

EndClass

/*/{Protheus.doc} New
  
  Constructor Method

  @author Lucas Fidélis
  @since 02/11/2021
  @version P12
  @param cSecret, String, Secret Key that will be used to generate the hash by HMAC
  @return Self
  /*/
Method New(cSecret) Class Jwt
  ::cSecret := cSecret
Return Self

/*/{Protheus.doc} Sign
  
  Returns a JsonWebToken as string
  
  @author Lucas Fidélis
  @since 02/11/2021
  @version P12
  @param  oPayload, Object, An object from JsonObject
  @return cToken, String, A new JsonWebToken
  /*/
Method Sign(oPayload) class Jwt

  Local cToken, cHeader, cPayload, cSign
  Local oHeader

  oHeader := JsonObject():New()
  oHeader["typ"] := "JWT"
  oHeader["alg"] := "HS256"  

  cHeader := StrTran(Encode64(oHeader:toJson()), "=", "")
  cPayload := StrTran(Encode64(oPayload:toJson()), "=", "")

  cSign := StrTran(Encode64(HMAC(cHeader + '.' + cPayload, ::cSecret, 5)), "=", "")

  cToken := cHeader+"."+cPayload+"."+cSign

Return cToken

/*/{Protheus.doc} Verify
  
  Returns if JsonWebToken is valid. If JsonWebToken is true and the param oPay is provided, oPay will be populated
    with a JsonObject

  @author Lucas Fidélis
  @since 02/11/2021
  @version P12
  @param  cToken, String, A JsonWebToken that will be validated
          oPay, Object, An object from JsonObject provided by reference
  @return lValid, Boolean, If JsonWebToken provided is valid 
          oPay, Object, Object provided by reference that will be populated with the informations from payload as JsonObject
  /*/
Method Verify(cToken, oPay) class Jwt

  Local aParts := StrTokArr(cToken, '.')
  Local cHeader := aParts[1]
  Local cPayload := aParts[2]
  Local cTokenValid

  cSign := StrTran(Encode64(HMAC(cHeader + '.' + cPayload, ::cSecret, 5)), "=", "")
  
  cTokenValid := cHeader+"."+cPayload+"."+cSign

  lValid := cToken == cTokenValid

  If lValid
    cPay := Decode64(cPayload)
    oPay:FromJson(cPay)
  EndIf  

Return lValid
