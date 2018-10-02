
rule n2319_139d2299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139d2299c2200b12"
     cluster="n2319.139d2299c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['22bfb590244ea8795d9f0b70b6a5c7289f6d4c87','65487379735d827d500e4d9745c28f8b4389e475','65b0ad49cb6b4ad2ca1ed5d1634073cdc7c5265e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139d2299c2200b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
