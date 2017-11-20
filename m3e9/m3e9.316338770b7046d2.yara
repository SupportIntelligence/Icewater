
rule m3e9_316338770b7046d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338770b7046d2"
     cluster="m3e9.316338770b7046d2"
     cluster_size="303"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['003cf7bf9827e1df51ac3d1aa7f05543','02b294a5efa8f6f10acc6b561c9f77ec','6064654dd4af17c3ece7528d3c4a4576']"

   strings:
      $hex_string = { d97d9c8c6b9b820bdcb73c68cea925d2f53241801b0be60119390451bcb0ab4b5d1761c9cb082d1d4e3d00071afaccef34cfb603715889a3c1382b555ad067ed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
