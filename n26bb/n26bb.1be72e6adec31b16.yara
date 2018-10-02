
rule n26bb_1be72e6adec31b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1be72e6adec31b16"
     cluster="n26bb.1be72e6adec31b16"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious androm backdoor"
     md5_hashes="['3221924ebee1db6fd789f050f4b92838960da748','9b2d09aa9ebd10a344336ed2ef0002fb62920fcb','1b2856471bbcc19a5a3c7ad92a6b3bd3e6fbe8fa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1be72e6adec31b16"

   strings:
      $hex_string = { eb0fe95c93feffbb03010380e8ba96feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c055688aa2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
