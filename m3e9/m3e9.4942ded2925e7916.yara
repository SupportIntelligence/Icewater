
rule m3e9_4942ded2925e7916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4942ded2925e7916"
     cluster="m3e9.4942ded2925e7916"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi wbna"
     md5_hashes="['446d4094452bd816e1164628c171063e','519ee948aad4f45358a44d1d6035a842','da55420fa9418716e1a3bdd6dfe86198']"

   strings:
      $hex_string = { 8a3400f401fccbe4fe6324ff0101276cff25750400e70808008a34009e210f08031958ff0858ff0dec0103001a58ff0504006424ffd8001b1300210f18031958 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
