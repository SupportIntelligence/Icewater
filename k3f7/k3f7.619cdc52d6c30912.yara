
rule k3f7_619cdc52d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.619cdc52d6c30912"
     cluster="k3f7.619cdc52d6c30912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['45b1ea15b76c222f3c63019f1c416011','95bd3cb273b87bfbde152e10467e83ae','f2e743409bce4cfbcbb95f3ea8aabb7b']"

   strings:
      $hex_string = { 363638316237656239346534375f584c2d313530783135302e6a706720313530772c20687474703a2f2f7777772e71756f74696469616e6f6c6976652e636f6d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
