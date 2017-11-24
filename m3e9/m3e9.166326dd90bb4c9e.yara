
rule m3e9_166326dd90bb4c9e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.166326dd90bb4c9e"
     cluster="m3e9.166326dd90bb4c9e"
     cluster_size="1825"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious adinstall"
     md5_hashes="['0021f1264112c69540cd3d5735004467','002d899f9d2af50e88624627bad72e7c','02c7676e201b4bd7a94fd6823798b7ee']"

   strings:
      $hex_string = { 238ad865322db03b9363cac7855d16215ab962067d55d6209ca9ff8b1ba11879eeac89cc0851f35bfc0f44989d04a488b6842e4b4605f16b40e27c07e7e64561 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
