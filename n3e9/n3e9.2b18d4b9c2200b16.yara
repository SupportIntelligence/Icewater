
rule n3e9_2b18d4b9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b18d4b9c2200b16"
     cluster="n3e9.2b18d4b9c2200b16"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor dealply malicious"
     md5_hashes="['02c938c34b2efa5b5852b9c5d5bd414c','1ba6252180f00473d5a91aeffdd9e8ce','f9cd148388187b67fca9939844e9524a']"

   strings:
      $hex_string = { 0043006f00640065003a002000250064002e000a00250073001b0041002000570069006e003300320020004100500049002000660075006e006300740069006f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
