
rule m2320_57c15ec1c8000312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.57c15ec1c8000312"
     cluster="m2320.57c15ec1c8000312"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macro malicious powload"
     md5_hashes="['08c20260ec0a2034e3e977e24b5ded9890b70838','65ef541a8725fcb72a50680e95f8544e84c86c78','733aa6c5f33192511fd9793c00f6061a66018850']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2320.57c15ec1c8000312"

   strings:
      $hex_string = { 9a536afda432fa6b4dc9c5433e95705b3c6675244820d5d17206840802b646176dff0010e9efab98335ccc31120f8cd5f0eaaafb0d048abdc261b1d7fe2994b2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
