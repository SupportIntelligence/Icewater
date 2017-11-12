
rule n3ed_39957a39caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a39caa00b32"
     cluster="n3ed.39957a39caa00b32"
     cluster_size="1757"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['00d3d0bb567992e56e127f6b04b838e3','011aee0cc212542a41b45a4749ea2fc4','0435f2b13c278baf6669b94524d88bae']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0dbc7f0510d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
