
rule n3e9_1bc69c99c6210b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc69c99c6210b16"
     cluster="n3e9.1bc69c99c6210b16"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious btsgeneric"
     md5_hashes="['38032bc75262603ccbf5bb94f7238f25','90db260c35db0ad5b505acea713d36ab','f068d0694f2b182bd02a6ff52c4904ce']"

   strings:
      $hex_string = { 0042006c007500650007004600750063006800730069006100040041007100750061000500570068006900740065000b004d006f006e00650079002000470072 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
