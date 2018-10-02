
rule k26bb_6ad2979911be2d96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6ad2979911be2d96"
     cluster="k26bb.6ad2979911be2d96"
     cluster_size="833"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nemesis dotdo nsis"
     md5_hashes="['c48e7616cf700fbe4d2fa5068eaabc22be86bde9','fbfcbf0aa0997eb0acb6a3a02b0b439cb050754b','ba84e488ddc819c79fc9debce55cea89aaf10e3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6ad2979911be2d96"

   strings:
      $hex_string = { f8ff152c71400085c07465837dd001755f395de87521807d0b0d742b807d0b0a74258a45f788043e463ac388450b74403b75cc7cbeeb390fb645f75057e8d733 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
