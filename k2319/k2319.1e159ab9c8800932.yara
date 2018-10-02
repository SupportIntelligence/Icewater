
rule k2319_1e159ab9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e159ab9c8800932"
     cluster="k2319.1e159ab9c8800932"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1a73f6a14854c8a9db8c97454809e6fc82a2f12c','48d32b33e252d0bc6a0ae6dfddb96d0cc3342b09','3c6366b5c53fd37d27c4ffc80b31267905e14708']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e159ab9c8800932"

   strings:
      $hex_string = { 46293c3d30783234433f2837332c313030293a28307835382c39362e324531292929627265616b7d3b666f72287661722070304420696e206532563044297b69 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
