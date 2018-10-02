
rule n3f8_6a93ad229ad30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6a93ad229ad30914"
     cluster="n3f8.6a93ad229ad30914"
     cluster_size="256"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos smsagent"
     md5_hashes="['acacc0e8b32751f933d9f0ffb7b7e9819c7e7fa6','0798a7a4d7d192bd3a4d417aefb53fdeb0bd8a0c','6d15b9d5c126943ff0c84edb7db851fe4718ca89']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6a93ad229ad30914"

   strings:
      $hex_string = { 070e872d6d3c87787802222c02571d699e5a960112134b4b5b6ab4b6896b01130f011c1178a5d2b402634a00a3030100070e69965a3cc3f051196901110d00b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
