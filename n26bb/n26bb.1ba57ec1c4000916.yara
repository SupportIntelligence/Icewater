
rule n26bb_1ba57ec1c4000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1ba57ec1c4000916"
     cluster="n26bb.1ba57ec1c4000916"
     cluster_size="2082"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pykspa agentwdcr vilsel"
     md5_hashes="['0f98fe4902b9ba7600a0dfe0883793cecb668397','7bfcbb55ac11eb325b8ac3e6af43986a3e9c3db4','6803eac0773fd73c79ff23b43039570f8015b545']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1ba57ec1c4000916"

   strings:
      $hex_string = { ff1514a2420032d283f8077d0583f80f7f1833c985c07e12803c312e7502fec2413bc87cf380fa03740432c05ec3b0015ec3558bec83ec40568b75086a208d45 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
