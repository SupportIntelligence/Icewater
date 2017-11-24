
rule k2321_233529589abf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.233529589abf4912"
     cluster="k2321.233529589abf4912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['07699a336d4dc98a09e37aee57d98325','14dab89e866b383fde8dddc84f1d3772','e4eee8ae72163c84be22ad9c6a2c9c9d']"

   strings:
      $hex_string = { e760ac701bb808e48b44c6977452b428c6c3eee5e80ef77f5b2adf7a6bd67dbb771d1ab0bd25b9d35e2f8c4aa59990a75f6ffef5719dd2597b85f66cba87026d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
