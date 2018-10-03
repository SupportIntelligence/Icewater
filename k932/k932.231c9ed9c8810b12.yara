
rule k932_231c9ed9c8810b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k932.231c9ed9c8810b12"
     cluster="k932.231c9ed9c8810b12"
     cluster_size="23092"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="flashback macos flashfake"
     md5_hashes="['fdb3429ccf153e5d338ca509daa799dc8983b5a9','bea6988c4bd77fe0850a19f17eb6ef9ff5f27e4e','af5dc2d4d2f0809ed6d11914cff1a159d613b1e7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k932.231c9ed9c8810b12"

   strings:
      $hex_string = { 1424ff154c63000089f08b65d88d65f45b5e5fc9c35589e55731ff5631f65331db83ec0c8b4d10eb5a8b451429d883f801760b80390d75068079010a74430fb6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
