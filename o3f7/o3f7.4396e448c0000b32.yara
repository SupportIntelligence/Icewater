
rule o3f7_4396e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f7.4396e448c0000b32"
     cluster="o3f7.4396e448c0000b32"
     cluster_size="520"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['00fff9a4e27c7969e775b3eeec93b589','0140ce7a3257188f7ddb3c6ef0d88d72','08a5f6add9ba8b51c3547fb67bac7718']"

   strings:
      $hex_string = { 53c4b04ec4b05a2054c39c524bc4b05945262333393b444520322e20545552204845594543414e493c2f613e0a3c7370616e206469723d276c7472273e283129 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
