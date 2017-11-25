
rule m2319_3b104a8eea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b104a8eea210912"
     cluster="m2319.3b104a8eea210912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['1932464828c8cd06d8b44ce81c8b1d16','8a5b8d0de680112dcd1cdc9e01e51880','af8ef174f0ba2bc40989dca20489e1ed']"

   strings:
      $hex_string = { 78473757525133355653342f7337322d632f486172726965745f5475626d616e5f66616d6f75735f626c61636b5f70656f706c652e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
