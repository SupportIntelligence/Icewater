
rule n26bb_061499e1c6010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.061499e1c6010b12"
     cluster="n26bb.061499e1c6010b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="genkryptik cgef khalesi"
     md5_hashes="['032bbe6b944c3fffa1f6f9c74b0f17a9c91f0acf','962546dfa3bc73bf6dbb969c14004ff06b2510f1','b6e6b9e1feb0de8c2ad382694e582eecb8d942cc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.061499e1c6010b12"

   strings:
      $hex_string = { dc8d4dd8e8efc8feffff75dc68d02e4000e8dac7feff33c985c00f9ec18b4510668b55e0662b1066f7da1bd2420bca85c90f85a70100006a228d45b850e8fac6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
