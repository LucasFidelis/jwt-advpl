#Include "Protheus.ch"

User Function JwtExample()

  Local cKey := "b44de0df9003385ea2431e35befff44fa0a3d51a"
  Local oPayload := JsonObject():New()
  Local oPay := JsonObject():New()

  oPayload["cUserId"] := '000000'

  oJwt := Jwt():New(cKey, 'SHA512')

  cToken := oJwt:Sign(oPayload)

  ConOut(cToken)

  If oJwt:Verify(cToken, @oPay)
    ConOut(oPay:toJson())
  EndIf
  
Return Nil
