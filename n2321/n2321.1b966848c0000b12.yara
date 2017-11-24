
rule n2321_1b966848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.1b966848c0000b12"
     cluster="n2321.1b966848c0000b12"
     cluster_size="40"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['02a5e7d5e8a89531d759e2f5f1b77480','050cab68224884441ba3763243fff6b2','68521f7d32004ad3d53535dd3ac7c260']"

   strings:
      $hex_string = { 9c44ed8259285162da6e9119977994c6c3f426d7d2ffa0a5a79e5f84ee330bcde6706c1242c045853fdff8226adc561b34484b084e9563fad021752a5335fb68 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
