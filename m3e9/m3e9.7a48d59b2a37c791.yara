
rule m3e9_7a48d59b2a37c791
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7a48d59b2a37c791"
     cluster="m3e9.7a48d59b2a37c791"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['804f6c6807e5687ec59f24390e4b4c02','a1ff192b39a616da0a142dd0471ad12a','eba0b4d81ba2b6cb0574ffd763015e96']"

   strings:
      $hex_string = { c8813e3c344300895db8895da8895da4895da07405e815b2fdff83c644391e750b5668e48e4000e8bdaffdff8b3e8d4da451578b07ff50243bc3dbe27d11bbd4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
