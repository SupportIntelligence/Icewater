
rule o26d4_1b9915a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.1b9915a9c8800b32"
     cluster="o26d4.1b9915a9c8800b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi neoreklami malicious"
     md5_hashes="['b8b62bdd7bfd1dab61327cd63c57eab4031f8305','978ad61385523971650738676464fa7faae29bc0','3b36834236a4095509edcce3ac0c5838ba6705ce']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.1b9915a9c8800b32"

   strings:
      $hex_string = { 4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708000040 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
