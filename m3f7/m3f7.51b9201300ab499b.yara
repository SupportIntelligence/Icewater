
rule m3f7_51b9201300ab499b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.51b9201300ab499b"
     cluster="m3f7.51b9201300ab499b"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['09a13e4eb46b63a983020cfa6d08799c','1bf933d9a872fc8ad4a943f5d2d3aaf1','d00a580e1c366f51f5626c2be1c31069']"

   strings:
      $hex_string = { a782205b62ef8d3f213fe7dcecc03f32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
