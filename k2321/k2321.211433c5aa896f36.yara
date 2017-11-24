
rule k2321_211433c5aa896f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211433c5aa896f36"
     cluster="k2321.211433c5aa896f36"
     cluster_size="15"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['06a8f728f34b357c6dc00b9c5a029902','0aa0c23c3e75b849532a76b7812c196e','e02f6cd8d0d10d3f7575368a4d415c17']"

   strings:
      $hex_string = { 2d682354874425c027065a08d521c31cbe917f5be9b6cf0f3113131f5febb1c8163a98e176ccaf37d71756678b89db3de877ef8f6fa92eb285d7d2509bfabca1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
