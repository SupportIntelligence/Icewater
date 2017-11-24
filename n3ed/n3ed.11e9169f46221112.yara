
rule n3ed_11e9169f46221112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.11e9169f46221112"
     cluster="n3ed.11e9169f46221112"
     cluster_size="68"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['022467cce16d05badda885169b17dd23','0351ca6ce0f1ea03b8b7e9862e378f2c','4b0cb9efeeb1b840e4b689b513ce2793']"

   strings:
      $hex_string = { 7e298d49008be8668b1966011c410fb71981e3ff0700008a1c3b4d881e83c1024685ed7fe22bd085d27fda5d5b5e83c40cc3cccccc83ec34dd05180904105355 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
