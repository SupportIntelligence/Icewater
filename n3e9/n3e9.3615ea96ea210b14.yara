
rule n3e9_3615ea96ea210b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3615ea96ea210b14"
     cluster="n3e9.3615ea96ea210b14"
     cluster_size="2434"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="auslogics malicious unwanted"
     md5_hashes="['000459ab45aa70b8602fc1a2be95080a','0009425363089eb40b69ff84f3924dac','01b00c5f6c4aac1c0822fd0f4a27898a']"

   strings:
      $hex_string = { 3c41ac024d96d45b07dbf708e83e12d37c14eb20d69f6331386dd8e6047fb1395baae4b3a221bf6f36a7288ad43e6c73ea65a336c783190b09466dcee09b119b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
