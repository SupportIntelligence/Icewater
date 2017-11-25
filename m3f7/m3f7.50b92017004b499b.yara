
rule m3f7_50b92017004b499b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.50b92017004b499b"
     cluster="m3f7.50b92017004b499b"
     cluster_size="8"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['07d5abe64aa5e9bc531f725c6b9e63a2','4ec6a8c0c981b22ba5f0afe335a66bec','f285d2dfedf3b950de221811837dcc89']"

   strings:
      $hex_string = { de8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b56886780399a3088476d6968e92888d0d1e7925a16919e8e066 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
