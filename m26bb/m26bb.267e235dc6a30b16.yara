
rule m26bb_267e235dc6a30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.267e235dc6a30b16"
     cluster="m26bb.267e235dc6a30b16"
     cluster_size="257"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adposhel malicious engine"
     md5_hashes="['99c1760d55aac7c479441a66cb383c4b5dbfe1f2','8100b8a081dd9fb3175c935d23fb6ad9babfbaef','50c7040a9fe33a28f08b6cceef0ebbb205b38c81']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.267e235dc6a30b16"

   strings:
      $hex_string = { e68078e9c53172bf01e42a8120525bf6a34f5415d0f090034762cc23186f3a33c8c387595e34c000a28541c653a9ff967abdd59e5664bc5fdfa86889f24b178d }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
