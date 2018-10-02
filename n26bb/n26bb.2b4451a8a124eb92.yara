
rule n26bb_2b4451a8a124eb92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b4451a8a124eb92"
     cluster="n26bb.2b4451a8a124eb92"
     cluster_size="200"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="slimware unwanted fakedriverupdate"
     md5_hashes="['e41561b1f21f6a2eaf4c0e9079df6946d36caffc','28544e6976a869f67fdbb5f729f516fbc883a5ee','5921a29d864be080c73c5abe0b1994ab41a3c346']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b4451a8a124eb92"

   strings:
      $hex_string = { 77696463746c7061725c66692d3336305c6c693732305c736131303020352e5c7461622041434b4e4f574c454447454d454e54204f4620434c4f55442d424153 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
