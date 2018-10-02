
rule k2319_3910f662ca42b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3910f662ca42b912"
     cluster="k2319.3910f662ca42b912"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['9664d0b2c2830300582026fbf79dc200c0530527','8ddcece4fbf328eee8dcae510115533b22c57722','4255c54be4e45b6980671a9151b68e3867d7689b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3910f662ca42b912"

   strings:
      $hex_string = { 28392e32303045322c3078323436292929627265616b7d3b7661722043394939343d7b274d3754273a227274222c27533834273a66756e6374696f6e28592c48 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
