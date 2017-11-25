
rule m2318_61b920279ad30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.61b920279ad30912"
     cluster="m2318.61b920279ad30912"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['28a3257b97c265ec2d57f028f2965ecd','2af8aa000799f960aa504083c269f012','dd9075828dbceebb24c103f637f9540b']"

   strings:
      $hex_string = { 39413332334437303543384632424531304438383135423145424131433037373734363439413643324442344142344433374336373336323946353646463532 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
