
rule m3e9_519bc9fad166d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.519bc9fad166d111"
     cluster="m3e9.519bc9fad166d111"
     cluster_size="446"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['00a20b168f6b846b0ce7e2b1926d7899','011531d6e7a49ed7dcce497744d14cc9','08499371e17f46ac36f52c97882b3846']"

   strings:
      $hex_string = { 04040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040440 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
