
rule o26d7_0b929ab0d1bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.0b929ab0d1bb0912"
     cluster="o26d7.0b929ab0d1bb0912"
     cluster_size="86"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="liev malicious cobalt"
     md5_hashes="['1a0eac78d52abcc458d5e33146a86b18f03cf657','ca007eafdc4d005be3d3e5d61e0e425f5bb4ef17','3b7632e18867d21ae04dc6e1e6efd78854f548f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.0b929ab0d1bb0912"

   strings:
      $hex_string = { 673b206220696e743634207d01001d2a783530392e4365727469666963617465496e76616c69644572726f72030006526561736f6e001561736e313a226f7074 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
