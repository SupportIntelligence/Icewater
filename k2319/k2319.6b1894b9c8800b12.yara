
rule k2319_6b1894b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6b1894b9c8800b12"
     cluster="k2319.6b1894b9c8800b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['c0e984971f961f1e4787656e24917faae2774db1','7f80b53bbd1b3841af03a20a44af17b4dbefc5b6','2bff11f890bc4b8b238159f57a5ace5dce24db9a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6b1894b9c8800b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20575b435d3b7d76617220773d2830783230343c3d283133372e2c3939293f2830783133432c226c22293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
