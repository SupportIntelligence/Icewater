
rule k2321_0b13a80986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b13a80986220b12"
     cluster="k2321.0b13a80986220b12"
     cluster_size="37"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['03913b0342d04e1a7be95760e99dfe36','0f526ae2d8efd9f402ee4df990167ef6','5a18a009d6eda0564738669c3fdabd42']"

   strings:
      $hex_string = { 1f5d4cfb932f49d7e607e9e2776239d094c319baca2776a1e4131a32702b52298275f9429f0bd97a567b24a03d91df122546bfef0549c96f3ec2f6bccd305c5f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
