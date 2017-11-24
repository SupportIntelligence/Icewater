
rule m2321_0b949518dee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b949518dee30b32"
     cluster="m2321.0b949518dee30b32"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['30e8b85c4c3bd82755e3a766ce89856d','54b97e012dea9a58a2aebccdbe06ea1c','f36b8ec7f7f12ffe1c5cb2eebfd115bd']"

   strings:
      $hex_string = { 8c65078873deaf62634aadc4ddf01066d3702ef874010f4d23cef414fdb17158d7a706b5bea1792df791990003485ceebf6b87704142e8c737eaeb9ea4dfbb9f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
