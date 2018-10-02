
rule k2319_291596b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291596b9c8800b32"
     cluster="k2319.291596b9c8800b32"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['92164abfda579333dad7a16757225bca2a3b383a','ae08ed5738b82b182a9b0f6a0d3d379f21cbf614','31db6c82e17c12255031c07208cf2fb6de459c79']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291596b9c8800b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20785b6b5d3b7d76617220513d2833392e3c2839312e2c30784238293f283132362c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
