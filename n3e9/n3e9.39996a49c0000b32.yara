
rule n3e9_39996a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39996a49c0000b32"
     cluster="n3e9.39996a49c0000b32"
     cluster_size="53"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor fynloski rmkfrcpqokas"
     md5_hashes="['0ada1afd9e84aff56aae69c3d0f5e4ea','0b308d775a821c9368e8008a15d79e0f','887e9374ea5cb7767224f49fb10f2409']"

   strings:
      $hex_string = { 6d596005689c3011c402367506102fefada8a6eceb1d1f78145af918b6379deb072b6108a3fc172101d5430c84b34455ac3223042d12b8ae2079c85191b562d2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
