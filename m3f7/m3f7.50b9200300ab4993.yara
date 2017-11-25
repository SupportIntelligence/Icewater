
rule m3f7_50b9200300ab4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.50b9200300ab4993"
     cluster="m3f7.50b9200300ab4993"
     cluster_size="18"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00fdefa2ace649065ca05401e9a0cbf8','1095fa77ab03a4aceeb99de2b725b028','decaf8fb6aa4e30bbe3a10170be5d1c0']"

   strings:
      $hex_string = { 0ea782205b62ef8d3f213fe7dcecc03f32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
