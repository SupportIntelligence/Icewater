
rule m3e9_319c9499c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.319c9499c2200b32"
     cluster="m3e9.319c9499c2200b32"
     cluster_size="371"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul krap"
     md5_hashes="['00d0f14a16b88623398cf245d9d0a19e','034de0a079ddbf5befb5e765e6f3b6d4','1ce8ef57589d5784ee22bf0316789ded']"

   strings:
      $hex_string = { ca742a44ada00401874695820fb051654c1299e819aa1000d2defa7f6b0e9bd926033c135d0df4767a9a75c240e07c174bb49dd98f1ee4cf89c78bda2ff55b32 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
