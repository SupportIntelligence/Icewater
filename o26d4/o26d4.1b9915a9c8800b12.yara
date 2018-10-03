
rule o26d4_1b9915a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.1b9915a9c8800b12"
     cluster="o26d4.1b9915a9c8800b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy neoreklami malicious"
     md5_hashes="['b7a989dba247ffcb4a597a0c5ee1f70141577099','e18ce42a9c5a763eb90c6fc6e8878fcf7431002a','b613ef8c51be8db75a284b4392b06ad4d5fe7b20']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.1b9915a9c8800b12"

   strings:
      $hex_string = { 0000dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
