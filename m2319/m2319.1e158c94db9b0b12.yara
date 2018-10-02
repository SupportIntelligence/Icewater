
rule m2319_1e158c94db9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1e158c94db9b0b12"
     cluster="m2319.1e158c94db9b0b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script classic"
     md5_hashes="['2f558773432fdfde6a0d1b691c72e0899fd1c48e','09363304eb9554adbec0be49bbbc9c5852152ead','ad8b980221ef8a0294ec7d2f75a1deb34e02c0b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1e158c94db9b0b12"

   strings:
      $hex_string = { 6368653a21312c747970653a757c7c22504f5354227d293b742e75706c6f616450726f6772657373262628732e7868723d66756e6374696f6e28297b76617220 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
