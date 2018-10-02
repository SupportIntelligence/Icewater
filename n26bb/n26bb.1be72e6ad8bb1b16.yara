
rule n26bb_1be72e6ad8bb1b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1be72e6ad8bb1b16"
     cluster="n26bb.1be72e6ad8bb1b16"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="debc malicious androm"
     md5_hashes="['014191767e5af9fda6815f0894d345d83b2749c0','4fd3afd42dec9b02174c1a67f28ee49fbc5eecac','b1b7280e7a89e8d6f8a4fc891cdc4ee244fc0801']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1be72e6ad8bb1b16"

   strings:
      $hex_string = { eb0fe95c93feffbb03010380e8ba96feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c055688aa2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
