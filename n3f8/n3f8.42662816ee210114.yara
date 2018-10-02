
rule n3f8_42662816ee210114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.42662816ee210114"
     cluster="n3f8.42662816ee210114"
     cluster_size="219"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos origin"
     md5_hashes="['6a3edafc554884b001f5c11329ff759f7f01df0f','58e6d0402544ccf0fec5e1e7db1ad1fa9dbd469e','a6d1236ecd27e6ff8abeaca3897f51bf540ecb91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.42662816ee210114"

   strings:
      $hex_string = { 08025460c0037220500f700070516409763228d65362c2039c02080270405f0926135a64c20328e75461c1037110390e00000c0072304f0f710028dd6e103006 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
