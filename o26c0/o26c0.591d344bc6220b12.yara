
rule o26c0_591d344bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.591d344bc6220b12"
     cluster="o26c0.591d344bc6220b12"
     cluster_size="240"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut attribute"
     md5_hashes="['2b5ec39ec52ac4fb65207a2ef03fc762f71bafe8','9d9338bb8b4832f413bb33100974692fbe06088a','0a2d4ccd78f3c7f9d6c1524573a46f5d0b7cac31']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.591d344bc6220b12"

   strings:
      $hex_string = { e869c929dfedaa27fffdc383116a47bba809399ea17282d2d9de16abf2c0ba7c106f6d04b1c852061ac6b21fa968fc863ec53721b543c44155a6367fd4cf75b4 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
