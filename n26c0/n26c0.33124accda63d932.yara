
rule n26c0_33124accda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.33124accda63d932"
     cluster="n26c0.33124accda63d932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious aruz"
     md5_hashes="['72aaca44f276fe4273f38b647ffbfb34defa414a','26bff7706cda4ee007a21012cb2a4b3a1bf721a5','ad20b9d97f2d51eda7e86c23cc48c5019e0afbbe']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.33124accda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
