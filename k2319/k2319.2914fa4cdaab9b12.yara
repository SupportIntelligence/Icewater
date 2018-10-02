
rule k2319_2914fa4cdaab9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2914fa4cdaab9b12"
     cluster="k2319.2914fa4cdaab9b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['86936a0ce794e0d394cad193e793d845994a03c8','0e3ba7e48255bde937b9aa3fa9a01e94275756be','bcb71341917090282c2726ad979364c73de0819f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2914fa4cdaab9b12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
