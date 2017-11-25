
rule m2319_2b93111289056d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b93111289056d16"
     cluster="m2319.2b93111289056d16"
     cluster_size="21"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['002c19af35151aebde177b16ae27b804','0902ef7664f236d951bf170e9fe153c8','d309156e03b9fbabeb71a538c52bd6a5']"

   strings:
      $hex_string = { 784d6f64756c6555726c273a202768747470733a2f2f7777772e626c6f676765722e636f6d2f7374617469632f76312f6a7362696e2f33323833303138353736 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
