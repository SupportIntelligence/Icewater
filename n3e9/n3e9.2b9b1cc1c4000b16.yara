
rule n3e9_2b9b1cc1c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b9b1cc1c4000b16"
     cluster="n3e9.2b9b1cc1c4000b16"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="heuristic corrupt corruptfile"
     md5_hashes="['00c47f2710de1d65564c8cd1a9f7b03d','26b77924cac7c1e4fd8222ac7718d6f9','eb1c47428c521ab4449b11425c1b97d3']"

   strings:
      $hex_string = { c745bb051d5e428bcf66c745b95f10c645b81c8a440db82c03343f88440db84183f9077cee68040100008d8594feffff5750e892a80a0033c083c40c3986a804 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
