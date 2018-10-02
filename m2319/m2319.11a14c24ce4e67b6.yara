
rule m2319_11a14c24ce4e67b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.11a14c24ce4e67b6"
     cluster="m2319.11a14c24ce4e67b6"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['fe616c35efbbc3acfca0f7a7faf582c1bcc1b954','27df4484a4898f959a25e3c47c92b3adc556d5cc','b71d1da5593b795ea838119bf2b6e8ba74c143cc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.11a14c24ce4e67b6"

   strings:
      $hex_string = { 68682822262378323033393b222c312c2d31293b746869732e5f6e61765f706d2e747469703d43616c656e6461722e5f54545b22505245565f4d4f4e5448225d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
