
rule k3f8_4cc25ec348000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.4cc25ec348000000"
     cluster="k3f8.4cc25ec348000000"
     cluster_size="538"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="metasploit hacktool androidos"
     md5_hashes="['70456a30fb2e932aad69ceae9e9853629ca2052c','57b683af033e2cb2d354ca2ed77842bd04d600e0','22a1cab9d8a979c2e01143e78f27c7974c69cf0a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.4cc25ec348000000"

   strings:
      $hex_string = { 69006e307400080a1a0001006e205e0009000c022123011035302d004604020071102a0004000a05390522001a0507006e305f0054070c042145337519004605 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
