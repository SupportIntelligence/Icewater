
rule k2319_293496b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.293496b9c8800932"
     cluster="k2319.293496b9c8800932"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e25934c1b15418c77317ebd70247bf480a81e383','1da9b4a7bf81a054fa99dd0508ffc56b314a571c','50e99c9c98256e26cbcea36795aca530daa4a14d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.293496b9c8800932"

   strings:
      $hex_string = { 2831362c3078313443292929627265616b7d3b76617220663248303d7b274a3969273a2268222c27663350273a322c274330273a66756e6374696f6e28532c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
