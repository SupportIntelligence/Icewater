
rule m3e9_4ab0d73657bf5112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4ab0d73657bf5112"
     cluster="m3e9.4ab0d73657bf5112"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik pronny"
     md5_hashes="['0b7067053c7e3ffce4a23eeaa24797f9','12f0c953234d600d4ad0386c540793e4','b1004367ff56c2bb68d12a1c452f9562']"

   strings:
      $hex_string = { 66676e5f6e59556f987a726f6d7990a2dcf9fffdfff7f7b7000000f8ffff0312282c20101111101a585765736c30667a635f5c75b3a79cc0cecdaea9aae6f2fa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
