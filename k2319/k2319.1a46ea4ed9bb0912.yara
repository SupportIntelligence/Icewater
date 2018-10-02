
rule k2319_1a46ea4ed9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a46ea4ed9bb0912"
     cluster="k2319.1a46ea4ed9bb0912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script codw"
     md5_hashes="['44a67d085f948db74569e82edb77f34aca6e7c0c','270894d573454f68e2f81ee5b3b890235ee70d6b','1ff62e9d8d4c354e4add02480df79a1dcdf58c13']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a46ea4ed9bb0912"

   strings:
      $hex_string = { 2830783133462c312e3431334533292929627265616b7d3b76617220793273355a3d7b2758315a273a66756e6374696f6e28592c6b297b72657475726e20597c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
