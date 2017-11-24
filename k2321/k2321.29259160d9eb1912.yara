
rule k2321_29259160d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29259160d9eb1912"
     cluster="k2321.29259160d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['23b2db415583847bdd900ec1f73b7f0a','3c7be4c906433901d33cd162ebe1e7e3','4e6578bce015a184895088fb45e685b1']"

   strings:
      $hex_string = { a223ab6f52b25b27ca5495e268d855dff39233fb7ce74b5aa7a01aeda19e01c3203bafdca32873d17b4e3230dd22171b96ec62439ab6bd00820cc24d10460b34 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
