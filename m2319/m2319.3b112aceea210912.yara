
rule m2319_3b112aceea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b112aceea210912"
     cluster="m2319.3b112aceea210912"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['0d7a7a4c4ef40dd0bae23340ac2dd358','1e15bd149186b555624715cf1f6fc7db','b3468255b418a503feb26a4d7b1303d3']"

   strings:
      $hex_string = { 78473757525133355653342f7337322d632f486172726965745f5475626d616e5f66616d6f75735f626c61636b5f70656f706c652e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
