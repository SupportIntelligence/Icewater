
rule k2318_739596b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.739596b9caa00b12"
     cluster="k2318.739596b9caa00b12"
     cluster_size="2440"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html generickd"
     md5_hashes="['dbe7c3c94d4e258e67ebad8fa32a932f6085bdd5','46ce7ff949313ba38b9e764e03f9e75566924d43','b3ccf6b3cbb87423ae393613e9e4fc2f41fa6515']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.739596b9caa00b12"

   strings:
      $hex_string = { 642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
