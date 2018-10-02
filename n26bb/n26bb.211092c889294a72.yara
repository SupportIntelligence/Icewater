
rule n26bb_211092c889294a72
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.211092c889294a72"
     cluster="n26bb.211092c889294a72"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious heuristic"
     md5_hashes="['f3e1b903a1b50451732b022d9f4dfb2bc908b1e5','5b8c4a202a2ce49754b705a6b0eceeee56a014d1','42623830c80bd20829bff6482ea4b439ab7efd30']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.211092c889294a72"

   strings:
      $hex_string = { 4e9698ce6f86b259fefc975c5361c18219d4f4738190af6e66bf3825c6b863015535f28bf35749055e3a45777dc07e32c84128ca99a10f793017edfd3660843e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
