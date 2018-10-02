
rule n26bb_231c5dca4a739912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.231c5dca4a739912"
     cluster="n26bb.231c5dca4a739912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="remoteadmin ammyy malicious"
     md5_hashes="['6100b6805a362708ff04633d24e7c435aee5fd85','0a72cc5ec2934495a5ade890fcc7ddeac20037df','4ae00579c2df441de1dcc220001e9a97f2061168']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.231c5dca4a739912"

   strings:
      $hex_string = { 02540613881439473b7df872c35e5b5fc9c20c00558bec83ec0c0fb7550833c05633f68bc846d3e63bd67c244083f8107eef8d45f468dce24a0050e8c15bfdff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
