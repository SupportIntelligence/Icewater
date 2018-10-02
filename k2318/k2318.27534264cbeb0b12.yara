
rule k2318_27534264cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27534264cbeb0b12"
     cluster="k2318.27534264cbeb0b12"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['9d6c726b0b867f4c4fb10d7ecc6e1ee7a288de97','4cb7e0408f0e3ad7cbed1d0d091d61c13a6e872f','d183a1fc4aec2071da622a2eb90b6ccd29842b49']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27534264cbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
