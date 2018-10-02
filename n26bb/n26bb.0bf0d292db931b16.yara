
rule n26bb_0bf0d292db931b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.0bf0d292db931b16"
     cluster="n26bb.0bf0d292db931b16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="heuristic malicious androm"
     md5_hashes="['bc8adb9ef719bbc7dbbaa9c173495631ce202e68','1ca3382dc46c53b811b0e2fb72428c2d93d9b673','24e25d55ab5979cf2722bb6a13d7af5a2111ff94']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.0bf0d292db931b16"

   strings:
      $hex_string = { eb0fe9e892feffbb03010380e84696feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c055683aa3410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
