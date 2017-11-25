
rule m3e9_33954e5fc2220b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33954e5fc2220b16"
     cluster="m3e9.33954e5fc2220b16"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['2b163795f6408c82ade56b9887fd760a','3a5d236c55d3b8b7d9ec70b148b5b393','f2e818ec83481ac674b3abab68ea17a4']"

   strings:
      $hex_string = { debd3ebcf87c12ffcc869b91fe1eb4d13c8197ef66edbe4ffb0cc5eae793c4eb99549264a970f167c75ca1fc2e6d79576df975cf2789d74bd9f2f45a3f2d7faa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
