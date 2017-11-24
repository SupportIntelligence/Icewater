
rule m2321_0b9a871adee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9a871adee30932"
     cluster="m2321.0b9a871adee30932"
     cluster_size="6"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery dynamer pemalform"
     md5_hashes="['0d02f72e1cdecc23ff83a9e936173bbd','4a7592ae628dfc5f31b762a1b5779025','fdda6920bc3ca2cd03849e59e5869ea8']"

   strings:
      $hex_string = { dd46c3c54356b48af8a54dce0f7bc8b9d59df0c9a7646227882110a8e41d22702ddfb8cb6879de8c0b8fa33985b5d0da93d3f7c75d9284ac534773825658a0c6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
