
rule k2318_52945adbee210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945adbee210912"
     cluster="k2318.52945adbee210912"
     cluster_size="824"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['c41265c9aa02ef9a2c5ef8b12772b068162b6ff7','797da93c370456a3ebabbaf46a13b4e13d912430','a748766db39355528f2f834150bc4778f308f331']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945adbee210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
