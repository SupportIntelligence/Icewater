
rule m2319_419c95e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.419c95e9c8800b12"
     cluster="m2319.419c95e9c8800b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="inor script decode"
     md5_hashes="['df3f9c61d90c4dcb42c34ab76f0d0376ee0e458b','97ca24dcbf3ea2e8482dae97018208e37cc9bbb2','bddd3c856591c05ea4c54c4e230150d0f28623da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.419c95e9c8800b12"

   strings:
      $hex_string = { 33393339333b0a6c696e652d6865696768743a20312e363b0a7d0a23626c6f672d7061676572207b0a666f6e742d73697a653a20313430250a7d0a23636f6d6d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
