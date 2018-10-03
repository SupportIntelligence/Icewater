
rule n26bf_03928808dfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.03928808dfa30912"
     cluster="n26bf.03928808dfa30912"
     cluster_size="2610"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious ainslot"
     md5_hashes="['78c230c08dadfa314090a4d7de7f90facceea402','26575c7780ed631270411a146e5d3419b484a232','e674581b6b2652bfe86cd1932e5f992a07def920']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.03928808dfa30912"

   strings:
      $hex_string = { 1c28c3f72934b717b3727bd6243cab09cedbfe113e9fe4028da0d5c44a805763602281924be1f984e7424d451b38be2fc2139e95e559e897a2580ae0b1a146f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
