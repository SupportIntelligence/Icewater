
rule k2319_185a9cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185a9cb9c8800b12"
     cluster="k2319.185a9cb9c8800b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['85296cc08ac33faa55cea0b7183440833d42bae1','da26423aa75fbdcc964289e7e64b1117863a8ae5','e334b44be7cb7a512f7102a44aab9324b830ba76']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185a9cb9c8800b12"

   strings:
      $hex_string = { 3c3d3133352e3f2831392c31293a28362e353345322c3132362e292929627265616b7d3b7661722072356133703d7b27473470273a66756e6374696f6e28552c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
