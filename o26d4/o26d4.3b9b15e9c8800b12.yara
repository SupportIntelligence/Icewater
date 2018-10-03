
rule o26d4_3b9b15e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.3b9b15e9c8800b12"
     cluster="o26d4.3b9b15e9c8800b12"
     cluster_size="52"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious neoreklami"
     md5_hashes="['28b67ce8c6aaa4e9a6d9a4e64849524bb11ecbb6','f42ed2725c44ef15d2523c9550203483f34ab743','371cc90c785220230d616d178185b1f467fade91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.3b9b15e9c8800b12"

   strings:
      $hex_string = { 0000dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
