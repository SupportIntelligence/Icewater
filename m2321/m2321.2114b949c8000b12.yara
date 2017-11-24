
rule m2321_2114b949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2114b949c8000b12"
     cluster="m2321.2114b949c8000b12"
     cluster_size="123"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0108d6162d1937a8d0e9b4262dae9947','02623d515bd4a50217650f8523b667b8','1e600f876e5b50c2a9c8ec43424b306c']"

   strings:
      $hex_string = { 3b456d7fa41f855aca31b48982b0cbb5d4e54f245d30d713705bb1a8b7d52150947e8f19906c9197016325583ee978bd970d3577f66e2f390ff05f23f13fbb7d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
