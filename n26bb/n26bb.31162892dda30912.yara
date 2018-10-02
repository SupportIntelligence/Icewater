
rule n26bb_31162892dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.31162892dda30912"
     cluster="n26bb.31162892dda30912"
     cluster_size="197"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nymaim malicious razy"
     md5_hashes="['79b097fb0aa12f02e001a0d8d1629b21a1276b3d','09c119bebfd941c5563e2c8e3e95ef4017607622','7da102e775f41dd26446f470dc81f9a4c905b6c8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.31162892dda30912"

   strings:
      $hex_string = { ae91466d2ccbee5ff122bf8107ec615cd0d52e5e1831e487dcb2643990fdd40b55ef5975146b766c8bffdec2f06acc0d5416a3bd300f2333709a7484ad2b15b6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
