
rule k2319_180d9ee9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.180d9ee9c8800912"
     cluster="k2319.180d9ee9c8800912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ab27ca652bf8b42078bc63817ed5d4919e117c58','2968e9ddaf2778c41cbbfe0e2e7228bcc73f384c','d4191f035df657ca52a9d4db529b04bce8931c5c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.180d9ee9c8800912"

   strings:
      $hex_string = { 39293a2833332e3545312c30783631292929627265616b7d3b76617220733579303d7b27783630273a222b2f222c27723258273a66756e6374696f6e28472c54 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
