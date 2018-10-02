
rule m26bb_269b5c5bbf6b0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.269b5c5bbf6b0b16"
     cluster="m26bb.269b5c5bbf6b0b16"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="firstfloor riskware toolbar"
     md5_hashes="['a272d5fc3bef6d9472b9dbf090069f54373c0604','2ccf3b9cec7fee8e9bc201b947c0fb0ff8e93a0d','8bad633e2106ccfefbbc1293cf4cf3fc7820d262']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.269b5c5bbf6b0b16"

   strings:
      $hex_string = { e94496cf55306c9e0f4693bc3f3f88b273387aa51d00000003204d6e233c8dc0bb4ea5d8f959a8d4bd4891c5a351a9dcff51a9dcff52a9dcff52abdeff52ade0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
