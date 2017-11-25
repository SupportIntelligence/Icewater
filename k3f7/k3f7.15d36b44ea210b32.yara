
rule k3f7_15d36b44ea210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d36b44ea210b32"
     cluster="k3f7.15d36b44ea210b32"
     cluster_size="25"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['0cc1cb0f93ae095d2652e73cc4e007ed','1108d8a464f6cb7efc24dec996fa75bc','b8d6680a7b62aa664d8980c942e4404b']"

   strings:
      $hex_string = { 6e742d617765736f6d652e637373227d5d7d20293b0a2f2a205d5d3e202a2f0a3c2f7363726970743e0a3c73637269707420747970653d27746578742f6a6176 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
