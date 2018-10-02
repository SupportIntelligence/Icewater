
rule k2319_1a5a8599c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5a8599c2200b12"
     cluster="k2319.1a5a8599c2200b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['25898dd067e46528dd7a7cb55ad75d3435da4f04','030fc0ea71b9c3b87ce8056abacd37023215fceb','a078286b0c4880af837cb5b07a1872c12dadf2a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5a8599c2200b12"

   strings:
      $hex_string = { 31302e2c39332e292929627265616b7d3b7661722077355a37563d7b27733256273a66756e6374696f6e28532c49297b72657475726e20533c493b7d2c274438 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
