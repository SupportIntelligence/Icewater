
rule n2319_311486d89ec96d36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.311486d89ec96d36"
     cluster="n2319.311486d89ec96d36"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['20d8cdace7ce754bee4701ebe904aa4450c6ee0b','a8ece37f4029b94ac7f37c0e506a2affc5df7e49','86e07a5d76beae224b8c4fa5f568e23a56319e14']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.311486d89ec96d36"

   strings:
      $hex_string = { 733d273132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
