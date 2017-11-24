
rule j2319_5994b73bc6200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5994b73bc6200b32"
     cluster="j2319.5994b73bc6200b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe iframem blacole"
     md5_hashes="['68d6adb154da37e93ee22229b1f73f50','a1079e42adbe8c2eedae6a350e2ecf4c','c22ffebf3a8bf230b9cb8c6f4d201c9e']"

   strings:
      $hex_string = { 696d67222c27706e67666978273a302c27776d6f6465273a307d293b7d293b0a20203c2f7363726970743e0a0a093c6c696e6b2072656c3d227374796c657368 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
