
rule nfc8_529a44a9c2cb4e5b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.529a44a9c2cb4e5b"
     cluster="nfc8.529a44a9c2cb4e5b"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="koler androidos ransom"
     md5_hashes="['9da2e497c3de4011ad3bfa5a150863eff1106cbb','9220a9196fa49107cba577d34639cc2fd578dbab','5d56aa46c171063842d4543e61aeda06d22cf0ec']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.529a44a9c2cb4e5b"

   strings:
      $hex_string = { ba68d65db153ca288517428000e8d7676dbcf0e26450d4f7c073ce33ec41e57bc8ab209203c4079339efcdc5ad77dc8e65cb7e434922e19b2990b09801dbb67d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
