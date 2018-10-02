
rule k2319_1e1596a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1596a9c8800932"
     cluster="k2319.1e1596a9c8800932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['838e9fb65f06e3818cb6a03b7c95c633631163a4','1fb4e099a5c7da807620e2da110af5b4b0fa424f','a8c3925dd5ae3d9921771fa14352672b00399a91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1596a9c8800932"

   strings:
      $hex_string = { 46293c3d30783234433f2837332c313030293a28307835382c39362e324531292929627265616b7d3b666f72287661722070304420696e206532563044297b69 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
