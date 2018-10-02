
rule n26bb_1b628a62dee31b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1b628a62dee31b16"
     cluster="n26bb.1b628a62dee31b16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fareit malicious filerepmalware"
     md5_hashes="['37183d1de44f345a76b19de5f6c88dfa6baaaa39','5c47f6d67fc4defecddaeca1e55a7831a1c872d0','684b599c2eb306dda6b67400fa3ccff268eabac3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1b628a62dee31b16"

   strings:
      $hex_string = { eb0fe93897feffbb03010380e8969afeff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c05568c69e410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
