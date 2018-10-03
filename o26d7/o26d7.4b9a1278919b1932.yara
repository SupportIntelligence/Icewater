
rule o26d7_4b9a1278919b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.4b9a1278919b1932"
     cluster="o26d7.4b9a1278919b1932"
     cluster_size="73"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="liev backdoor eadfad"
     md5_hashes="['385554f7f8e9e8f270bc5a0255f2dab2ed3d1f79','588cd2e864b3ceaaecdd25dd0f0cae7e9c17e7a9','fa364832522a446949be9886b7881947ab5dd47e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.4b9a1278919b1932"

   strings:
      $hex_string = { 673b206220696e743634207d01001d2a783530392e4365727469666963617465496e76616c69644572726f72030006526561736f6e001561736e313a226f7074 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
