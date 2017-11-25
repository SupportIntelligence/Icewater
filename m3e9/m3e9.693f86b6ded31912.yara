
rule m3e9_693f86b6ded31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f86b6ded31912"
     cluster="m3e9.693f86b6ded31912"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['172ba5bb00e9b42eaacef7c8552cbad8','699580808290e97eccf17a746c2dddfb','ff0b063a43a4023a623edd266ad02158']"

   strings:
      $hex_string = { caa268f2aba187b7fbce7b365a44f9d858e047c257d74906a8c563d9134d0802752c83dbec4feeb3e1bd99fa29ad6e1f5cfe69dab6e5536793a4796b7810d051 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
