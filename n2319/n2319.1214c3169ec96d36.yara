
rule n2319_1214c3169ec96d36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.1214c3169ec96d36"
     cluster="n2319.1214c3169ec96d36"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['874ab03416dd7ae0897664a720d6f86f0dad9ec9','d519a0bb0d4bfc8413b672aedb4afe6eb264879c','d2719001422cba0561a654750cbbb63b32f23cbc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.1214c3169ec96d36"

   strings:
      $hex_string = { 733d273132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
