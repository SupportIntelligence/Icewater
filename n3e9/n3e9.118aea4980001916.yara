
rule n3e9_118aea4980001916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.118aea4980001916"
     cluster="n3e9.118aea4980001916"
     cluster_size="77"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['0af71d78dbd63d3d895fc305c5066aa7','13c8d06bd2df2a742f5785fe4abcf69e','4598243dd7d97f963457555b9d001b17']"

   strings:
      $hex_string = { c1654c3ddad4378dc6f330e0ccc54850647271ec6608944d798754ae0bef6c45ed8e9fa0b1219852b21569afb8dbe8579234622c5909869c00391e01f804d3c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
