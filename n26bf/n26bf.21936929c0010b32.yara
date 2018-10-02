
rule n26bf_21936929c0010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.21936929c0010b32"
     cluster="n26bf.21936929c0010b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="msilperseus malicious agen"
     md5_hashes="['72d29429d9efc1894c3e74b0b6270566d4001098','05713d5b2e7275b2112c8ac39a75c1cde8818708','b140bc33e05bb8f34922088962361a64746c4526']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.21936929c0010b32"

   strings:
      $hex_string = { 37cb6012020b69103b127bb974e9d225ced93d2771e68e9989d3b64e330d9c35f061ad36b59ee5f7cfc51a14f462c3cae42691fbb08595bd55b8cc53a473e28b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
