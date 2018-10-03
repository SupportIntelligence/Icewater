
rule i26bb_32ac924caa3b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26bb.32ac924caa3b0912"
     cluster="i26bb.32ac924caa3b0912"
     cluster_size="2257"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd highconfidence malicious"
     md5_hashes="['07b91fc5cdfcd321f2b98e55cdee4a490c2ad1f9','6c951db6e2b7783fef7242c9391e445071652e62','cba08e87e2bbf2eb7386ca90be53baa21d9d0efa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26bb.32ac924caa3b0912"

   strings:
      $hex_string = { c72b594212d82d601a0e8fd65c158582e800a489dc43fadb20406936f15b37fdf99de7103cb3e606e2513454906c2fec7cce9992a5a27cec68c2c89604a6639a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
