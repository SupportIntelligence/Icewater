
rule n26bb_49b4d4539a630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.49b4d4539a630912"
     cluster="n26bb.49b4d4539a630912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="emotet dangerousobject filerepmalware"
     md5_hashes="['fc7288ba4872d6ed51bf08059cf1525ff413f336','14b8a6979e504fc4a9379d3ccc0dc2bcfdc6306b','6a678601251e268685bbb980e1609ebb104a3a50']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.49b4d4539a630912"

   strings:
      $hex_string = { 1088b6068147c4fdafac3fe70db7f2ad037f435f3d804d8b3e45e681f9c265ca44407024baf4b9137dee78141e5e7e97f04e9a5c6e914a53988f1d1b1661c694 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
