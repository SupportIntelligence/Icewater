
rule m2318_6b99a808d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.6b99a808d9bb0912"
     cluster="m2318.6b99a808d9bb0912"
     cluster_size="102"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['007ce4ebc7687e1265b8a3a149f8fb0a','011eb9cf6ce75cb6508e964e4547a4dd','1e6abaf032b82c8ac8565c8a9ce0f586']"

   strings:
      $hex_string = { 42364337453939353641333746414530344344303941453232384437443436314237314235423246383238393833364438354543344441354638334632333031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
