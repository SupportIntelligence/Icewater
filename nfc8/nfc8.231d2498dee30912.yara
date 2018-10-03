
rule nfc8_231d2498dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.231d2498dee30912"
     cluster="nfc8.231d2498dee30912"
     cluster_size="70"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos revo"
     md5_hashes="['e3adab56e6f88b8b9ac73985fef89d68192376b8','0f37c2d7c40695671ce25917ebc051e2cf99f237','2a6d8e62e1d374271cb227f7cb4071ad85f3904b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.231d2498dee30912"

   strings:
      $hex_string = { ba290c769131f85c2870b80a83d541b274332e8a8736b72d86f2e7513ad6edd2e3731b66c6b62792da018dd899b37a0d60f49b9d5b6732dfe5f6597d8b785e4b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
