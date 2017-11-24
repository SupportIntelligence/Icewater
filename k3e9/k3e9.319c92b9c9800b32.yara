
rule k3e9_319c92b9c9800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.319c92b9c9800b32"
     cluster="k3e9.319c92b9c9800b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jqap small trojandownloader"
     md5_hashes="['30710673de3fc5df6bd97a5719fe83c9','86b22a6a93f6454f26df049f07920996','e96ccc41bf90f1c8262e1d8dfb9cf9b2']"

   strings:
      $hex_string = { c7f5a72fc370b0ba3259eb36494b71e9b264fcc4830e0c0bcb95689194d2b12bd84a5fcc0882efcfe7670f0e7a62b4999738f939dbda1568c11b28939e54de63 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
