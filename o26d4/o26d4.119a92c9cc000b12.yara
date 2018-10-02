
rule o26d4_119a92c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.119a92c9cc000b12"
     cluster="o26d4.119a92c9cc000b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy neoreklami malicious"
     md5_hashes="['50ead5f44277222ef335b4ed166bb5391aa8739f','ecd49aa87f87ce9e37f30cb6a1ea374d9a8e6993','68437a50b47e9df1dc775706ec37943f0159f29e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.119a92c9cc000b12"

   strings:
      $hex_string = { 00dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f0010070800 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
