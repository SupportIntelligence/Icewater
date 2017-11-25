
rule k3e9_613c5f17da9b1b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.613c5f17da9b1b32"
     cluster="k3e9.613c5f17da9b1b32"
     cluster_size="52"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['09013a8c3790592eb7d2ac3d1901e74f','1339dc58f15debf65ef01f9eede50bd8','64777b3a40e479b8c25a340b53f5c3c8']"

   strings:
      $hex_string = { 8d4a0c89480889410483649e440033ff4789bc9ec40000008a46438ac8fec184c08b4508884e437503097804ba000000808bcbd3eaf7d22150088bc35f5e5bc9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
