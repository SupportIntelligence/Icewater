
rule n231e_491613696a220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231e.491613696a220912"
     cluster="n231e.491613696a220912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mobidash androidos addisplay"
     md5_hashes="['8e20942cbacef32428d0997e032d08d5ae374769','b5b4bb3569d350dcc3bfcb416f57da8f236ad9c2','ff7f4e0a39c984e8d45c6d4581c48713204407cb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231e.491613696a220912"

   strings:
      $hex_string = { e08d50f43b9358fdffff75158b45088d65f45b5e5f5dc2040090e853f2ffffeba183c9fff00fc148fc85c97fdf8b45cc89142489442404e8064a0300ebce89c6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
