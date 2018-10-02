
rule k2318_52945a5bee210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945a5bee210912"
     cluster="k2318.52945a5bee210912"
     cluster_size="418"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['bbb9074d0e52c16975b55abdd446d54d0b508ee7','4596a6e37c8f902c7be73282f62f0b1eb045cc60','b8948b6d1043e95f40ae80aa8d604e9ad4a1647a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945a5bee210912"

   strings:
      $hex_string = { 683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
