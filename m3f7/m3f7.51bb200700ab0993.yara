
rule m3f7_51bb200700ab0993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.51bb200700ab0993"
     cluster="m3f7.51bb200700ab0993"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1ceb28b21de4a46257122dc47d918087','58f72f3a8eb7ab7827a3d5964d27e77e','f5a9527e1b5a8b76dc651bc0d8558714']"

   strings:
      $hex_string = { 32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b56886780399a30884 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
