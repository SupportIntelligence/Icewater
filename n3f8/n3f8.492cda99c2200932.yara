
rule n3f8_492cda99c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.492cda99c2200932"
     cluster="n3f8.492cda99c2200932"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smsspy androidos smsthief"
     md5_hashes="['6511829f289f3114a43c666759965d4a872f20c7','c4382fc7ddb58b7d30ccdaa7d3fc1f8a8e9efa42','ab3ce70137c4a98793d781ec37b9c98f530e2cdb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.492cda99c2200932"

   strings:
      $hex_string = { 76614d61696c2e00034a756c00034a756e00094b4545505f5345454e00074b4559574f524400074b53433536303100084b6579776f72647300014c00064c4152 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
