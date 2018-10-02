
rule k2318_339b92b9caa00912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339b92b9caa00912"
     cluster="k2318.339b92b9caa00912"
     cluster_size="111"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['15c77333edc96208214ddad24ed52f092600da20','bc96b43f1688443526672d3db23e9667a9d34115','9cba9b54c15699f4cf964e4c42a4d8bc5c048ba9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339b92b9caa00912"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
