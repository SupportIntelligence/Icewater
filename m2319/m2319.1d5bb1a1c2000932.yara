
rule m2319_1d5bb1a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d5bb1a1c2000932"
     cluster="m2319.1d5bb1a1c2000932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['70f3f9e10be89160a55d90609dd21bd3acf3173d','ed7c0c456ac9b77de562cff34970be70983b9bd9','fc5f246a0ad22687d3525052a9eead636ad2541b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d5bb1a1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
