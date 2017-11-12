
rule m3e9_6934e46dca210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6934e46dca210b32"
     cluster="m3e9.6934e46dca210b32"
     cluster_size="13097"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz xgal"
     md5_hashes="['0000b8a0eb87a843cae1d9c5b8b635f1','0006fa084ae239baae420f97a14c8dd4','0060b7614c8bdc20e1c82789ab25d0db']"

   strings:
      $hex_string = { e234d699262cbe7d78e5b8a2ef6459fb2ff0ed42f46039eef89019b1933bce0689b1e70475c814e1cbf7df12e0ba0967ec079de9def2033fa3f9f59701b0afb2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
