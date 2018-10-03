
rule j26bf_14a85eb91ec31130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.14a85eb91ec31130"
     cluster="j26bf.14a85eb91ec31130"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious dangerousobject"
     md5_hashes="['389daeb52a582a2efc0eadca7d06f43ec71dbadd','c83e35a3cc4bc3d46e080c0060416ce879a0af4e','49ae434d4cebfa99a1895d7e5f4a84f264cecc2f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.14a85eb91ec31130"

   strings:
      $hex_string = { 11157519000001131711172c0711176f2500000adc111417581314111411138e693f8ffeffff083979feffffdd5b020000261f1c282600000a72930300707320 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
