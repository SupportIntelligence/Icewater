
rule o3ed_109d6a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.109d6a49c0000b32"
     cluster="o3ed.109d6a49c0000b32"
     cluster_size="64"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursu pakes avqm"
     md5_hashes="['00ba41faaf060352071382ecde03b9b3','00efe2ac4b84319d4a76ed8073339baa','409751d3db7b8e60e3311aa1bc7b0b5a']"

   strings:
      $hex_string = { 47b714f6821b4c1cc70b3a362256c420669c9821a29d1311534e4360edc6dfa7009472861f4024899093ce33492d64cf8327684558e036188c2fb410c92e1c6f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
