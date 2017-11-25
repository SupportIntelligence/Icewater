
rule m3f7_59b9200300ab499b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.59b9200300ab499b"
     cluster="m3f7.59b9200300ab499b"
     cluster_size="17"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['12c6fdf30de34a75e5a3c4aef7d65e10','19ec0748c757e970a1245b7733c4f486','f3b869de7037427a79bc6686bef370d0']"

   strings:
      $hex_string = { a782205b62ef8d3f213fe7dcecc03f32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
