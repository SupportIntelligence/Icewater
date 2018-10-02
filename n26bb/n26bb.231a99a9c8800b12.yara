
rule n26bb_231a99a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.231a99a9c8800b12"
     cluster="n26bb.231a99a9c8800b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="proxy bunitu fqaw"
     md5_hashes="['b23052b8c3ab1e3aab19f11dcae343ecfb164880','eea96eeedf2744caf95edba6cb75405479c285be','82dbe87789527eb788f6c681d4065f1e7cb0b49a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.231a99a9c8800b12"

   strings:
      $hex_string = { 42463ac374034f75f33bfb75108819e8e7f6ffff6a225989088bf1ebc133c05f5e5b5dc38bff558bec8b4d085633f63bce7c1e83f9027e0c83f9037514a1cc54 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
