
rule i2319_4bb2952ad726d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.4bb2952ad726d111"
     cluster="i2319.4bb2952ad726d111"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos expkit html"
     md5_hashes="['e3073739997e92b1e7df56a3d2e6fea15f0c8d76','4bc58b5014eeabf206f870a49365ddceae972674','48576ff2cd6454321ebd1c41c4308c5063e75e20']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.4bb2952ad726d111"

   strings:
      $hex_string = { 537472696e6728293b0d0a09090d0a2020202076617220615f616c6c5f636f6f6b696573203d20646f63756d656e742e636f6f6b69652e73706c69742820273b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
