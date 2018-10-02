
rule o2319_339b9cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.339b9cc1c8000b12"
     cluster="o2319.339b9cc1c8000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['2692438cce51219dce7f1796ab19b64ede431cf6','72247616549008a78cb49659a3bda6edbacfba07','c4fbba33656dd52133206daf701d132a0b9a90b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.339b9cc1c8000b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
