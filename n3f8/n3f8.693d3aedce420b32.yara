
rule n3f8_693d3aedce420b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.693d3aedce420b32"
     cluster="n3f8.693d3aedce420b32"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="droidkungfu androidos kungfu"
     md5_hashes="['58b2c3273a6307a84e2b728f5731258e6e91ed17','285f1fb94f34f3b03221269d18245a04ed2a7f94','192ebaa9ff235dac74b61c28dc91c1d7031306bf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.693d3aedce420b32"

   strings:
      $hex_string = { 0040303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
