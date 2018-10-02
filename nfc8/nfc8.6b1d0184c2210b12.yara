
rule nfc8_6b1d0184c2210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.6b1d0184c2210b12"
     cluster="nfc8.6b1d0184c2210b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos revo"
     md5_hashes="['a4f381659b5e512e948ea7f445bb8a462200242e','652a7b6d11eed328363aa61ca69987b9349a3e92','c422c8b7733594a9800ff22c9e1fc9e842c19ea6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.6b1d0184c2210b12"

   strings:
      $hex_string = { ba290c769131f85c2870b80a83d541b274332e8a8736b72d86f2e7513ad6edd2e3731b66c6b62792da018dd899b37a0d60f49b9d5b6732dfe5f6597d8b785e4b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
