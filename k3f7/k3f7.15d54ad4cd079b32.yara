
rule k3f7_15d54ad4cd079b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d54ad4cd079b32"
     cluster="k3f7.15d54ad4cd079b32"
     cluster_size="22"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['0bee828cd5f392961f7acbb38a7e5a5b','11d790405101c4df3ab39f6b576a55a1','b6e0edd880eddb77f343ff1f80543f3a']"

   strings:
      $hex_string = { 292e7374796c652e646973706c6179203d20276e6f6e65273b7d3c2f7363726970743e0d0a093c2f626f64793e0a3c2f68746d6c3e0d0a3c212d2d2050657266 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
