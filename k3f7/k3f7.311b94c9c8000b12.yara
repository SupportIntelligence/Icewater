
rule k3f7_311b94c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.311b94c9c8000b12"
     cluster="k3f7.311b94c9c8000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['05e988ac48b5f3e77c5f5742f72b9564','366e931fdf11543f09b59f089bc6b7fb','f385ddea9480af3672701ab2d560fcb1']"

   strings:
      $hex_string = { 6e6773293b0a09090a0a2f2a203c215b43444154415b202a2f0a76617220736d705f76617273203d207b22636f6f6b69655f6964223a22313437363833303236 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
