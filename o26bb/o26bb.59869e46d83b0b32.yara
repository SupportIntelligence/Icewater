
rule o26bb_59869e46d83b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.59869e46d83b0b32"
     cluster="o26bb.59869e46d83b0b32"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="safebytes malicious attribute"
     md5_hashes="['09cce201fb57ea93464ef4520a9e28fb853bc31e','a6d590adc892ea02caad5b33a5f7357bb14918e7','60c38df14f580dbd54e8573957beb46bb6c026b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.59869e46d83b0b32"

   strings:
      $hex_string = { c3e9e495f4ffebd85f5e5b8be55dc2040000d85332b02077684bb10ae3e79b91ecd3175f39d0aa52154593a55b292f03aa7b05278ce85a7c664e9b81447d05d5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
