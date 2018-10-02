
rule j2319_611a17c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.611a17c9c4000b12"
     cluster="j2319.611a17c9c4000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug megasearch browsermodifier"
     md5_hashes="['150d412174b0a80b0c51704a63a98da8ac5acb4d','aa999049b86d963ab7aa9c29a6188a61f870448f','a8bc5a810cad7a03a2aa88a38ceda3ece881ec8c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.611a17c9c4000b12"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
