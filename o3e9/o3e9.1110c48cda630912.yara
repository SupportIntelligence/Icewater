
rule o3e9_1110c48cda630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1110c48cda630912"
     cluster="o3e9.1110c48cda630912"
     cluster_size="2773"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="advml backdoor dragon"
     md5_hashes="['00298a028f6bdbf37d0beb508cdcaf2a','002af2fdf88ccbb055147993cefd43b4','0185e056dd5204c4a27fff667188c3f8']"

   strings:
      $hex_string = { 66b704b091c836571623a107a6dd7818c68ecbe6f89dfd5497380405554fc848acbf462c901d967bf75231d36a236c56a4d17d4515327d3cd7ba250b02bb6a41 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
