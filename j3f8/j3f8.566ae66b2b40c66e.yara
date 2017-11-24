
rule j3f8_566ae66b2b40c66e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.566ae66b2b40c66e"
     cluster="j3f8.566ae66b2b40c66e"
     cluster_size="13"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jisut ransom androidos"
     md5_hashes="['0e9b437d30eb665c7ac8e2fa5f6adedd','12216c79249eb851b77c8c7b2ba19ed0','fef34d337df61979d1319cc7c4a3e2ad']"

   strings:
      $hex_string = { 77696474680008776d506172616d730001780001790005e8be93e585a5e5af86e7a081efbc810004e99a8fe69cbae7a0813a000c4c636f6d2f682f522469643b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
