
rule m3f8_210b0da1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.210b0da1c2000932"
     cluster="m3f8.210b0da1c2000932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos andr"
     md5_hashes="['62b49d138852c647d3616d58de2fbf358a0e4cd4','7b3dad244f59f1e46e8898687f7c9f7e1a19b229','a3a8ad49a540f223a8d8e72422c96002108e5624']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.210b0da1c2000932"

   strings:
      $hex_string = { 154c6f72672f6a736f6e2f4a534f4e4f626a6563743b000c4d414e554641435455524552000e4d41585f4241434b4f46465f4d53000b4d43727970742e6a6176 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
