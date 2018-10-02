
rule m26bb_69bf3336d4696ab6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.69bf3336d4696ab6"
     cluster="m26bb.69bf3336d4696ab6"
     cluster_size="244"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['1a544de2bb35d16a49d1d5665399d7cd18196e58','6ceff5e7ce59bb30507ba34c13965b2153d882bc','46185f630a45f925fcbd147080d1a5a382434b05']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.69bf3336d4696ab6"

   strings:
      $hex_string = { a00b8fedcd20cb3b38e32f9c6eefbdd67a367f8dbc9d215e022765bbee895f0f6baf777d3ee55a299952a2b1ea5598d4003d63b63ae0dd2ca89141185d7e64a4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
