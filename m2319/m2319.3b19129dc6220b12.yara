
rule m2319_3b19129dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b19129dc6220b12"
     cluster="m2319.3b19129dc6220b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['b397b14a3303f821922bdc8df48be5d5','ca543aef991a60a46ff75fbb2d8b88bc','fcd983321a8d330ef9ae5c8fd5305c65']"

   strings:
      $hex_string = { 743e0a3c6c696e6b20687265663d27687474703a2f2f332e62702e626c6f6773706f742e636f6d2f2d3465784f725f5136415a512f555f6a79774a48414d4b49 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
