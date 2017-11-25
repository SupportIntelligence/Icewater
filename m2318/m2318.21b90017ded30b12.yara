
rule m2318_21b90017ded30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.21b90017ded30b12"
     cluster="m2318.21b90017ded30b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0707f867a456b4c3058728d06b6bc6b1','3799f3ccb103895d4e7e03ebc57ab1a4','cf47803012b0293ddb0862ade205b91f']"

   strings:
      $hex_string = { 4f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f534352495054 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
