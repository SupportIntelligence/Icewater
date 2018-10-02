
rule k26bb_5a98487bc964d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.5a98487bc964d111"
     cluster="k26bb.5a98487bc964d111"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="yontoo browsefox grayware"
     md5_hashes="['d27840388d65e871753793056a647b855660ec51','5da88d068dc916c462f2f7fb6751ed671fb38227','bac510dbe04743a99c7d54e0428a2217039f5723']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.5a98487bc964d111"

   strings:
      $hex_string = { 996e83121fac81215b2dfccf492cdbed4e927ccbf0c4e125885e70b2a8905d3d8ebb56fda19880e0557f410c308a9733d8942ad184a5afc987a2de92651806e6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
