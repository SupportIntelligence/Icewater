
rule n3f8_1399b949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.1399b949c0000b12"
     cluster="n3f8.1399b949c0000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot adlibrary eyzuao"
     md5_hashes="['bbad1805aef88bf20cd7f69be9c85b6f1f3c87b7','90d614b8c1e6016a9b6747ff279f94afd1763fd5','d775ecaa361fde6db21d53e644735a625b1b3de3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.1399b949c0000b12"

   strings:
      $hex_string = { 46696c7465723b00194c616e64726f69642f67726170686963732f4d61747269783b001a4c616e64726f69642f67726170686963732f4f75746c696e653b0018 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
