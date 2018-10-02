
rule j2319_291cb6e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.291cb6e9c8800b12"
     cluster="j2319.291cb6e9c8800b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem megasearch multiplug"
     md5_hashes="['5d51c2af5050bcfe34df5b1b6b57ea66af0f5606','c19517d97d76be79a4287ce9cc9c3685e12c8502','7af0b4fcbd0c3e144369de66fcdf50a508bc9f8e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.291cb6e9c8800b12"

   strings:
      $hex_string = { 696e67735d0a5265706f72743d227b43383738333445422d413241302d423944342d414139412d4332363344313139313035317d220a44656661756c74436f6d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
