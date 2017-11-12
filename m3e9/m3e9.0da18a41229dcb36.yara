
rule m3e9_0da18a41229dcb36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0da18a41229dcb36"
     cluster="m3e9.0da18a41229dcb36"
     cluster_size="18599"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cripack yakes tpyn"
     md5_hashes="['001756e953e1c1a432cf8160ee9bef8a','001c9e9ec3d803ed725cd94573290ce4','0076473321a5de0ed0cccf110984e488']"

   strings:
      $hex_string = { ff8701750008ef46f8e400487968a58b020083d0eb559cff40f836eb002cfa000021a54df19c006550e600f1ff00ff4cbb9c4a893e33d0004580032de08bf8eb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
