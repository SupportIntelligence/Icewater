
rule n3ed_39957a39c9800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a39c9800b32"
     cluster="n3ed.39957a39c9800b32"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['13fef0c5457ad24cc9bb476e9cdf4d91','2b1cc1503fc5a9f4cfc4a7713faef6ff','c709b3d1a4dc93525ac8d3cec3df4afa']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0dbc7f0510d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
