
rule k2321_23352958daabd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.23352958daabd912"
     cluster="k2321.23352958daabd912"
     cluster_size="4"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['1e8647c6328d92a294507b4feb45a35d','5bbb766a76eb6ddc4123f2d569db2e32','d0334656dd8a02f2a2462cbac82e5e4d']"

   strings:
      $hex_string = { e760ac701bb808e48b44c6977452b428c6c3eee5e80ef77f5b2adf7a6bd67dbb771d1ab0bd25b9d35e2f8c4aa59990a75f6ffef5719dd2597b85f66cba87026d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
