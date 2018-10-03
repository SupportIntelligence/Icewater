
rule n2319_393146a69daf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.393146a69daf4912"
     cluster="n2319.393146a69daf4912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['d8631b69cc7e71602f675980cf8fbdfc2b766710','33b93c456328d1dcfd1d8b70c0d33c7e4fbda725','22bb4aab41c144851cf8412b8c8b6f57b44c3bd6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.393146a69daf4912"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
