
rule k3e9_2114ed68989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2114ed68989b0b12"
     cluster="k3e9.2114ed68989b0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet vbkrypt"
     md5_hashes="['175f30643c6d9ea9358d3b54be5b8956','2bc132113c54a6441b4429db89f1630c','e0e9fc09630a94ce2ce9869d1572c7b2']"

   strings:
      $hex_string = { 8be5d8d16360de07efbfd7cee7952c169785925d486225c21242b458a4944afcd52a4491607f1df6c40883d6a022bd064bc01ec4a7bc9cec575edc7ef0871f70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
