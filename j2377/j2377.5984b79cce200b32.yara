
rule j2377_5984b79cce200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.5984b79cce200b32"
     cluster="j2377.5984b79cce200b32"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe iframem blacole"
     md5_hashes="['0986ae285cf5e5133635719a3d017f22','2014de7c7d739eb03fa1bc0c508104ee','b9ebcf166b74fd26fe5a6410d596bea6']"

   strings:
      $hex_string = { 3e0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e22 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
