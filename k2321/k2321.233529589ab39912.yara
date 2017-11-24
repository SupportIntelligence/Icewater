
rule k2321_233529589ab39912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.233529589ab39912"
     cluster="k2321.233529589ab39912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['0ec5602cc2daa3da3a2ae33dc92d937b','b8e93c16e5c5247e6c4afe8084e23872','d8fd6465cc94503c705c6d6bba1365fd']"

   strings:
      $hex_string = { e760ac701bb808e48b44c6977452b428c6c3eee5e80ef77f5b2adf7a6bd67dbb771d1ab0bd25b9d35e2f8c4aa59990a75f6ffef5719dd2597b85f66cba87026d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
