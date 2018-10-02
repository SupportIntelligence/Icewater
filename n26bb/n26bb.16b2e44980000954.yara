
rule n26bb_16b2e44980000954
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.16b2e44980000954"
     cluster="n26bb.16b2e44980000954"
     cluster_size="2647"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['d2952ef982c7c0cf70927a4772bca520ab5109fd','44153e9e1382ec6ff7a7553575b6279d3eb21c57','bab5c1b87be62922423c511bb5de74489251c20d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.16b2e44980000954"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
