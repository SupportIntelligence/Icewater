
rule k3e9_668c2b25c92b6916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.668c2b25c92b6916"
     cluster="k3e9.668c2b25c92b6916"
     cluster_size="179"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna vobfus chinky"
     md5_hashes="['08e9ea4c5cfcded006bfba6957d9f623','099a9d8e44ea45cd963e6d06c89e8b4f','467cb0b9681beff937fb54117e98c6ed']"

   strings:
      $hex_string = { 2a4658ff10800703006b56ff7054ff3558ff000b6b54fff4ffc61c13030019800c00761a002a234cff6c78ffe4f4fffe5d20102f4cff001d6c78ffe45e1b0004 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
