
rule k2321_0b1a9cc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b1a9cc9cc000912"
     cluster="k2321.0b1a9cc9cc000912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['500e5dfef6698654bac3b9f3903ea324','52b9396a65df31f05c7fbef8066f6d4c','d0caee02a540436115ef20c09e107854']"

   strings:
      $hex_string = { dc1789c3c5df4a1fc94355a7f94bc696e4665f83690e8b63cb729f78076a39aa2764ff3a9b913e7c8ef69e30463d87236676770ffbcd0c6ec7da5198ec745301 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
