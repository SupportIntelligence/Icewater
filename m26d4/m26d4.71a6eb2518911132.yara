
rule m26d4_71a6eb2518911132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.71a6eb2518911132"
     cluster="m26d4.71a6eb2518911132"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch mindspark malicious"
     md5_hashes="['91773baae74afb5d27a23cff44d7a133fd260ab0','2c277602095cc3290ae50109c370159622895cf4','9de9e9cd35cb31c16dcf7a0028c0b35b680ae54a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.71a6eb2518911132"

   strings:
      $hex_string = { 040200000f387e83504f5055504d454e555f434c415353571500536b696e20312e302054797065204c696272617279571c0050736575646f205472616e737061 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
