
rule n26bb_1be2a5a7fe610916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1be2a5a7fe610916"
     cluster="n26bb.1be2a5a7fe610916"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor heuristic hploki"
     md5_hashes="['086c991e75946b13dfa1e422660d21499daf4719','64c0e436453fa26bba5f3ad6b2b01d54cc6bc570','5da6a9d5aa878b3a9a434bf594fcb318f67645c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1be2a5a7fe610916"

   strings:
      $hex_string = { eb0fe93093feffbb03010380e88e96feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c05568cea2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
