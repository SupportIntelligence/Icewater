
rule j3f8_5891bc32d0ab9310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5891bc32d0ab9310"
     cluster="j3f8.5891bc32d0ab9310"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos ransom slocker"
     md5_hashes="['58632ef59af1d1c662fc79f401ae4d45ea870e0b','222c5d5ab01c1e68a11948fe83a6bedc46cbabcf','ea1b98b3e634264c503b742e189e7b0579288615']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5891bc32d0ab9310"

   strings:
      $hex_string = { 636b0009726f6f745368656c6c0006746869732430000576616c756500010a000328295600013c00043e3b5a2900053e3b5a5a29000c434f4d4d414e445f4558 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
