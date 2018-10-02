
rule n26bb_29ad12c4d0b96b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.29ad12c4d0b96b92"
     cluster="n26bb.29ad12c4d0b96b92"
     cluster_size="2103"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="safebytes riskware dllkit"
     md5_hashes="['cd1a4800a2bae2860846a8331a5cbb3ccb23fef6','850b316282f7a8bf7d681d424b7d3d264a78c0e6','444b115bc8e87c33c8162d5487f0d3a6cbb289e3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.29ad12c4d0b96b92"

   strings:
      $hex_string = { 10f30657c677f849ad1c2e38aaf0e1e1c172dfc5307b2383f526082b680a02b7a11fac4ea050bbc4b23b4a1d3f46bd988689649496293a8dd643d2049b561a0f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
