
rule k2319_491d46ebc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.491d46ebc2220b12"
     cluster="k2319.491d46ebc2220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive script"
     md5_hashes="['a703ee9fd42c7ba476b81fa46016cf2ff36685ef','8e97d74f1e324b84e37c10981bdc0b345cd7f827','98a74c374cea7157b79755cc7cb7820cc6d575c7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.491d46ebc2220b12"

   strings:
      $hex_string = { 2e77332e6f72672f313939392f7868746d6c223e0a3c686561643e0a093c73637269707420747970653d22746578742f6a617661736372697074223e2866756e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
