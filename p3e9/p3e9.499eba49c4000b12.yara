
rule p3e9_499eba49c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.499eba49c4000b12"
     cluster="p3e9.499eba49c4000b12"
     cluster_size="151"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['142b5a417d82c2542918293956613ac0','172662187ecceb6e422cfba065b5050d','643afc7e6b0f6bcaa50ee4762d684b8f']"

   strings:
      $hex_string = { f3cdabfff0caa9ffedc7a8ffe9c3a5ffe6c0a3ffe2bca1ffdeb89fffdab49effd6b19bffd3ad99ffcfaa97ffcca696ffc9a494ffb17f73ff030303230b0b0b0b }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
