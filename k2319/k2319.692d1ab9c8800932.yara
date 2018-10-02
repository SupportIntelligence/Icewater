
rule k2319_692d1ab9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.692d1ab9c8800932"
     cluster="k2319.692d1ab9c8800932"
     cluster_size="202"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['78961945ebb22a76778a95914ba73efaed0f9ba9','f0c5ebb05f6d69a49befde4f2f6a992ce8e6b0bd','42843a659eb86e60dedfaba3f363fa81c4155dc6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.692d1ab9c8800932"

   strings:
      $hex_string = { 307837432c3134392e292929627265616b7d3b76617220533353334e3d7b276d3671273a2274696d222c277a3471273a22696e222c274b374e273a2866756e63 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
