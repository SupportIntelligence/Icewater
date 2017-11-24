
rule k2321_0b13c80986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b13c80986220b12"
     cluster="k2321.0b13c80986220b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['30bc5308cdcbd977da75433e381ca766','3c1166671045c6262e71f56615b7c42b','e6ad42819efaa368de5fd21e36fc78e2']"

   strings:
      $hex_string = { 1f5d4cfb932f49d7e607e9e2776239d094c319baca2776a1e4131a32702b52298275f9429f0bd97a567b24a03d91df122546bfef0549c96f3ec2f6bccd305c5f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
