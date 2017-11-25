
rule m3f7_5ab92007008b499b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.5ab92007008b499b"
     cluster="m3f7.5ab92007008b499b"
     cluster_size="3"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3062c70ae6d2af5f8c48a25c4656c164','4fbbc04db629eea936e5d5cbe664ff3b','843e290c6eb97de7d9f30f7912707b47']"

   strings:
      $hex_string = { e7dcecc03f32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b5688678 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
